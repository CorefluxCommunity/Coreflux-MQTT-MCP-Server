"""
Enhanced logging system for Coreflux MCP Server

This module provides structured logging with rotation, filtering,
and enhanced security features for production environments.
"""

import logging
import logging.handlers
import os
import json
import sys
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path

class StructuredFormatter(logging.Formatter):
    """Formatter that outputs structured JSON logs"""
    
    def __init__(self, include_extra_fields: bool = True):
        super().__init__()
        self.include_extra_fields = include_extra_fields
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        # Import here to avoid circular imports
        try:
            from server import sanitize_log_message
        except ImportError:
            # Fallback if server module not available
            def sanitize_log_message(msg):
                return msg
        
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': sanitize_log_message(record.getMessage()),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields if enabled
        if self.include_extra_fields:
            for key, value in record.__dict__.items():
                if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 
                              'pathname', 'filename', 'module', 'lineno', 
                              'funcName', 'created', 'msecs', 'relativeCreated',
                              'thread', 'threadName', 'processName', 'process',
                              'exc_info', 'exc_text', 'stack_info']:
                    try:
                        # Ensure value is JSON serializable
                        json.dumps(value)
                        log_entry[key] = value
                    except (TypeError, ValueError):
                        log_entry[key] = str(value)
        
        return json.dumps(log_entry, ensure_ascii=False)


class SecurityFilter(logging.Filter):
    """Filter to ensure sensitive information is not logged"""
    
    def __init__(self):
        super().__init__()
        self.sensitive_patterns = [
            'password', 'passwd', 'pwd', 'api_key', 'token', 'secret',
            'authorization', 'credential', 'private_key', 'cert'
        ]
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter out potentially sensitive log records"""
        message = record.getMessage().lower()
        
        # Check for sensitive patterns in the message
        for pattern in self.sensitive_patterns:
            if pattern in message and '[REDACTED]' not in message:
                # Log a warning about potential sensitive data
                print(f"WARNING: Potentially sensitive data detected in log: {record.levelname} - {record.module}")
                return False
        
        return True


class LogManager:
    """Manages logging configuration for the Coreflux MCP Server"""
    
    def __init__(self):
        self.loggers: Dict[str, logging.Logger] = {}
        self.log_dir = Path("logs")
        self.ensure_log_directory()
    
    def ensure_log_directory(self):
        """Ensure log directory exists with proper permissions"""
        self.log_dir.mkdir(exist_ok=True)
        
        # Set appropriate permissions on Unix-like systems
        try:
            os.chmod(self.log_dir, 0o755)
        except (OSError, AttributeError):
            # Windows or permission error
            pass
    
    def setup_logger(
        self,
        name: str,
        level: str = "INFO",
        use_json: bool = False,
        enable_rotation: bool = True,
        max_file_size: int = 10 * 1024 * 1024,  # 10MB
        backup_count: int = 5,
        enable_security_filter: bool = True
    ) -> logging.Logger:
        """Set up a logger with the specified configuration"""
        
        if name in self.loggers:
            return self.loggers[name]
        
        logger = logging.getLogger(name)
        logger.setLevel(self._get_log_level(level))
        
        # Clear any existing handlers
        logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stderr)
        if use_json:
            console_handler.setFormatter(StructuredFormatter())
        else:
            console_handler.setFormatter(
                logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
            )
        
        # Add security filter if enabled
        if enable_security_filter:
            console_handler.addFilter(SecurityFilter())
        
        logger.addHandler(console_handler)
        
        # File handler with rotation if enabled
        if enable_rotation:
            log_file = self.log_dir / f"{name}.log"
            
            if max_file_size > 0:
                file_handler = logging.handlers.RotatingFileHandler(
                    log_file,
                    maxBytes=max_file_size,
                    backupCount=backup_count,
                    encoding='utf-8'
                )
            else:
                file_handler = logging.FileHandler(log_file, encoding='utf-8')
            
            if use_json:
                file_handler.setFormatter(StructuredFormatter())
            else:
                file_handler.setFormatter(
                    logging.Formatter(
                        '%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s'
                    )
                )
            
            # Add security filter to file handler too
            if enable_security_filter:
                file_handler.addFilter(SecurityFilter())
            
            logger.addHandler(file_handler)
        
        # Prevent propagation to avoid duplicate logs
        logger.propagate = False
        
        self.loggers[name] = logger
        return logger
    
    def setup_application_logging(
        self,
        app_name: str = "CorefluxMCP",
        level: str = "INFO",
        structured_logging: bool = None,
        enable_rotation: bool = True
    ) -> logging.Logger:
        """Set up logging for the main application"""
        
        # Auto-detect if we should use structured logging
        if structured_logging is None:
            # Use structured logging in production (when not in a TTY)
            structured_logging = not sys.stderr.isatty()
        
        # Check environment for logging preferences
        log_format = os.environ.get('LOG_FORMAT', '').lower()
        if log_format == 'json':
            structured_logging = True
        elif log_format == 'text':
            structured_logging = False
        
        return self.setup_logger(
            name=app_name,
            level=level,
            use_json=structured_logging,
            enable_rotation=enable_rotation
        )
    
    def get_logger(self, name: str) -> Optional[logging.Logger]:
        """Get an existing logger by name"""
        return self.loggers.get(name)
    
    def list_log_files(self) -> list:
        """List all log files in the log directory"""
        try:
            return [f.name for f in self.log_dir.iterdir() if f.is_file() and f.suffix == '.log']
        except OSError:
            return []
    
    def get_log_stats(self) -> Dict[str, Any]:
        """Get statistics about log files"""
        stats = {
            'log_directory': str(self.log_dir),
            'log_files': [],
            'total_size_bytes': 0,
            'active_loggers': len(self.loggers)
        }
        
        try:
            for log_file in self.log_dir.glob('*.log*'):
                if log_file.is_file():
                    file_stats = log_file.stat()
                    stats['log_files'].append({
                        'name': log_file.name,
                        'size_bytes': file_stats.st_size,
                        'modified': datetime.fromtimestamp(file_stats.st_mtime).isoformat()
                    })
                    stats['total_size_bytes'] += file_stats.st_size
        except OSError as e:
            stats['error'] = str(e)
        
        return stats
    
    def cleanup_old_logs(self, max_age_days: int = 30):
        """Clean up log files older than specified days"""
        try:
            import time
            cutoff_time = time.time() - (max_age_days * 24 * 60 * 60)
            
            removed_files = []
            for log_file in self.log_dir.glob('*.log.*'):  # Rotated log files
                if log_file.is_file() and log_file.stat().st_mtime < cutoff_time:
                    try:
                        log_file.unlink()
                        removed_files.append(log_file.name)
                    except OSError:
                        pass
            
            if removed_files:
                main_logger = self.get_logger("CorefluxMCP")
                if main_logger:
                    main_logger.info(f"Cleaned up {len(removed_files)} old log files")
            
            return removed_files
        except Exception as e:
            return f"Error during cleanup: {str(e)}"
    
    @staticmethod
    def _get_log_level(level_name: str) -> int:
        """Convert string log level to logging constant"""
        level_map = {
            'NONE': 100,  # Custom level higher than CRITICAL
            'CRITICAL': logging.CRITICAL,
            'ERROR': logging.ERROR,
            'WARNING': logging.WARNING,
            'INFO': logging.INFO,
            'DEBUG': logging.DEBUG,
        }
        return level_map.get(level_name.upper(), logging.INFO)


# Global log manager instance
_log_manager: Optional[LogManager] = None

def get_log_manager() -> LogManager:
    """Get or create the global log manager instance"""
    global _log_manager
    
    if _log_manager is None:
        _log_manager = LogManager()
    
    return _log_manager

def setup_logging(level: str = "INFO") -> logging.Logger:
    """Set up logging for the application (backwards compatible)"""
    log_manager = get_log_manager()
    return log_manager.setup_application_logging(level=level)

def create_child_logger(parent_name: str, child_name: str) -> logging.Logger:
    """Create a child logger with the same configuration as parent"""
    return logging.getLogger(f"{parent_name}.{child_name}")
