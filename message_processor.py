"""
Asynchronous message processing for Coreflux MCP Server

This module provides non-blocking message processing capabilities
to improve server performance under high message loads.
"""

import asyncio
import threading
import queue
import logging
import time
import json
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime, timedelta
from collections import defaultdict, deque

class MessageProcessor:
    """Asynchronous message processor for MQTT messages"""
    
    def __init__(self, logger: logging.Logger, max_buffer_size: int = 10000):
        self.logger = logger
        self.max_buffer_size = max_buffer_size
        
        # Message buffers
        self.message_queue = queue.Queue(maxsize=max_buffer_size)
        self.processed_messages = defaultdict(lambda: deque(maxlen=100))  # Keep last 100 per topic
        
        # Processing statistics
        self.stats = {
            'messages_received': 0,
            'messages_processed': 0,
            'messages_dropped': 0,
            'processing_errors': 0,
            'start_time': datetime.now()
        }
        
        # Processing control
        self.processing_active = False
        self.processor_thread = None
        self.message_handlers: Dict[str, Callable] = {}
        
        # Rate limiting
        self.rate_limits = defaultdict(lambda: deque(maxlen=100))  # Track message times per topic
        self.rate_limit_threshold = 50  # Messages per minute per topic
        
    def start_processing(self):
        """Start the message processing thread"""
        if self.processing_active:
            self.logger.warning("Message processor already running")
            return
        
        self.processing_active = True
        self.processor_thread = threading.Thread(
            target=self._process_messages_loop,
            name="MessageProcessor",
            daemon=True
        )
        self.processor_thread.start()
        self.logger.info("Message processor started")
    
    def stop_processing(self):
        """Stop the message processing thread"""
        if not self.processing_active:
            return
        
        self.processing_active = False
        if self.processor_thread and self.processor_thread.is_alive():
            self.processor_thread.join(timeout=5.0)
        
        self.logger.info("Message processor stopped")
    
    def register_handler(self, topic_pattern: str, handler: Callable[[str, str, Dict], None]):
        """Register a message handler for a topic pattern"""
        self.message_handlers[topic_pattern] = handler
        self.logger.debug(f"Registered handler for topic pattern: {topic_pattern}")
    
    def add_message(self, topic: str, payload: str, metadata: Optional[Dict] = None) -> bool:
        """
        Add a message to the processing queue
        Returns True if message was added, False if queue is full
        """
        if not self._check_rate_limit(topic):
            self.stats['messages_dropped'] += 1
            self.logger.warning(f"Rate limit exceeded for topic: {topic}")
            return False
        
        message = {
            'topic': topic,
            'payload': payload,
            'metadata': metadata or {},
            'timestamp': datetime.now(),
            'id': f"{topic}_{int(time.time() * 1000)}"
        }
        
        try:
            self.message_queue.put_nowait(message)
            self.stats['messages_received'] += 1
            return True
        except queue.Full:
            self.stats['messages_dropped'] += 1
            self.logger.warning(f"Message queue full, dropping message for topic: {topic}")
            return False
    
    def get_recent_messages(self, topic: str, limit: int = 10) -> List[Dict]:
        """Get recent messages for a topic"""
        messages = list(self.processed_messages.get(topic, []))
        return messages[-limit:] if messages else []
    
    def get_all_recent_messages(self, limit: int = 50) -> List[Dict]:
        """Get recent messages from all topics"""
        all_messages = []
        for topic, messages in self.processed_messages.items():
            all_messages.extend([{**msg, 'topic': topic} for msg in messages])
        
        # Sort by timestamp and return most recent
        all_messages.sort(key=lambda x: x.get('timestamp', datetime.min), reverse=True)
        return all_messages[:limit]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get processing statistics"""
        uptime = datetime.now() - self.stats['start_time']
        queue_size = self.message_queue.qsize()
        
        return {
            **self.stats,
            'uptime_seconds': int(uptime.total_seconds()),
            'queue_size': queue_size,
            'queue_utilization': f"{(queue_size / self.max_buffer_size) * 100:.1f}%",
            'processing_rate': self._calculate_processing_rate(),
            'active_topics': len(self.processed_messages),
            'registered_handlers': len(self.message_handlers)
        }
    
    def clear_buffers(self):
        """Clear all message buffers"""
        # Clear processed messages
        self.processed_messages.clear()
        
        # Clear message queue
        while not self.message_queue.empty():
            try:
                self.message_queue.get_nowait()
            except queue.Empty:
                break
        
        # Reset statistics
        self.stats.update({
            'messages_received': 0,
            'messages_processed': 0,
            'messages_dropped': 0,
            'processing_errors': 0,
            'start_time': datetime.now()
        })
        
        self.logger.info("Message buffers cleared")
    
    def _process_messages_loop(self):
        """Main message processing loop"""
        self.logger.info("Message processing loop started")
        
        while self.processing_active:
            try:
                # Get message with timeout to allow checking processing_active
                message = self.message_queue.get(timeout=1.0)
                self._process_single_message(message)
                self.stats['messages_processed'] += 1
                
            except queue.Empty:
                continue  # Timeout reached, check if we should continue
            except Exception as e:
                self.stats['processing_errors'] += 1
                self.logger.error(f"Error in message processing loop: {str(e)}")
        
        self.logger.info("Message processing loop stopped")
    
    def _process_single_message(self, message: Dict):
        """Process a single message"""
        topic = message['topic']
        payload = message['payload']
        metadata = message['metadata']
        
        try:
            # Store in processed messages buffer
            processed_msg = {
                'payload': payload,
                'timestamp': message['timestamp'],
                'id': message['id'],
                'metadata': metadata
            }
            self.processed_messages[topic].append(processed_msg)
            
            # Find and call appropriate handlers
            handlers_called = 0
            for pattern, handler in self.message_handlers.items():
                if self._topic_matches_pattern(topic, pattern):
                    try:
                        handler(topic, payload, metadata)
                        handlers_called += 1
                    except Exception as e:
                        self.logger.error(f"Error in message handler for {pattern}: {str(e)}")
            
            if handlers_called == 0:
                self.logger.debug(f"No handlers found for topic: {topic}")
            
        except Exception as e:
            self.logger.error(f"Error processing message for topic {topic}: {str(e)}")
    
    def _check_rate_limit(self, topic: str) -> bool:
        """Check if message rate limit is exceeded for a topic"""
        now = datetime.now()
        cutoff = now - timedelta(minutes=1)
        
        # Clean old entries
        topic_times = self.rate_limits[topic]
        while topic_times and topic_times[0] < cutoff:
            topic_times.popleft()
        
        # Check rate limit
        if len(topic_times) >= self.rate_limit_threshold:
            return False
        
        # Add current time
        topic_times.append(now)
        return True
    
    def _calculate_processing_rate(self) -> float:
        """Calculate messages processed per second"""
        uptime = datetime.now() - self.stats['start_time']
        if uptime.total_seconds() == 0:
            return 0.0
        
        return self.stats['messages_processed'] / uptime.total_seconds()
    
    def _topic_matches_pattern(self, topic: str, pattern: str) -> bool:
        """Check if a topic matches a pattern (supports MQTT wildcards)"""
        # Simple wildcard matching for MQTT topics
        # + matches single level, # matches multiple levels
        
        if pattern == '#':
            return True
        
        topic_parts = topic.split('/')
        pattern_parts = pattern.split('/')
        
        # If pattern doesn't end with #, lengths must match
        if not pattern.endswith('#') and len(topic_parts) != len(pattern_parts):
            return False
        
        for i, pattern_part in enumerate(pattern_parts):
            if pattern_part == '#':
                return True  # # matches everything after this point
            
            if i >= len(topic_parts):
                return False
            
            if pattern_part != '+' and pattern_part != topic_parts[i]:
                return False
        
        return True


class MessagePersistence:
    """Handle message persistence to prevent memory issues"""
    
    def __init__(self, logger: logging.Logger, max_memory_messages: int = 1000):
        self.logger = logger
        self.max_memory_messages = max_memory_messages
        self.memory_storage = defaultdict(lambda: deque(maxlen=100))
        self.overflow_storage = {}  # Could be implemented with SQLite or file storage
        
    def store_message(self, topic: str, message: Dict) -> bool:
        """Store a message, using memory or persistence as needed"""
        try:
            self.memory_storage[topic].append(message)
            
            # Check if we need to move old messages to persistent storage
            total_messages = sum(len(deque_obj) for deque_obj in self.memory_storage.values())
            
            if total_messages > self.max_memory_messages:
                self._move_to_persistent_storage()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error storing message: {str(e)}")
            return False
    
    def get_messages(self, topic: str, limit: int = 10) -> List[Dict]:
        """Retrieve messages for a topic"""
        # Get from memory first
        memory_messages = list(self.memory_storage.get(topic, []))
        
        # If we need more and have persistent storage, get from there
        if len(memory_messages) < limit and topic in self.overflow_storage:
            # Implementation would retrieve from persistent storage
            pass
        
        return memory_messages[-limit:]
    
    def _move_to_persistent_storage(self):
        """Move older messages to persistent storage"""
        # This could be implemented with SQLite, files, or external storage
        # For now, we just remove oldest messages
        
        for topic, messages in self.memory_storage.items():
            if len(messages) > 50:  # Keep only recent 50 in memory
                # In a full implementation, save the removed messages
                removed_count = len(messages) - 50
                for _ in range(removed_count):
                    if messages:
                        messages.popleft()
        
        self.logger.debug("Moved older messages to make room in memory")


# Global message processor instance
_message_processor: Optional[MessageProcessor] = None

def get_message_processor(logger: logging.Logger) -> MessageProcessor:
    """Get or create the global message processor instance"""
    global _message_processor
    
    if _message_processor is None:
        _message_processor = MessageProcessor(logger)
        _message_processor.start_processing()
    
    return _message_processor

def shutdown_message_processor():
    """Shutdown the global message processor"""
    global _message_processor
    
    if _message_processor is not None:
        _message_processor.stop_processing()
        _message_processor = None
