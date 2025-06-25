"""
Custom Redis Watcher for Casbin Policy Synchronization

This module implements a Redis-based watcher for Casbin that enables policy synchronization
across multiple application instances in a distributed environment. When policies are updated
on one instance, all other instances are notified via Redis pub/sub and reload their policies.

This implementation follows the Casbin Watcher interface and provides:
- Real-time policy synchronization via Redis pub/sub
- Automatic policy reloading on updates
- Configurable Redis connection settings
- Graceful error handling and fallback behavior
- Proper resource cleanup

**Security Note**: This watcher uses Redis pub/sub which sends messages in plaintext.
Ensure Redis connections use SSL/TLS in production and restrict access to authorized
instances only (OWASP A02:2021 - Cryptographic Failures).
"""

import asyncio
import json
import logging
import threading
import time
from typing import Optional, Callable, Dict, Any

import redis
from casbin.persist.watcher import Watcher

logger = logging.getLogger(__name__)


class RedisWatcher(Watcher):
    """
    Redis-based watcher for Casbin policy synchronization across distributed instances.
    
    This watcher implements the Casbin Watcher interface and uses Redis pub/sub to notify
    all application instances when policies are updated, ensuring consistent policy
    enforcement across a distributed deployment.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        password: Optional[str] = None,
        db: int = 0,
        channel: str = "casbin_policy_updates",
        **kwargs
    ):
        """
        Initialize the Redis watcher with connection parameters.

        Args:
            host (str): Redis server hostname.
            port (int): Redis server port.
            password (Optional[str]): Redis password for authentication.
            db (int): Redis database number to use.
            channel (str): Redis pub/sub channel for policy updates.
            **kwargs: Additional Redis connection parameters.
        """
        self.host = host
        self.port = port
        self.password = password
        self.db = db
        self.channel = channel
        self.redis_client: Optional[redis.Redis] = None
        self.pubsub: Optional[redis.client.PubSub] = None
        self.update_callback: Optional[Callable] = None
        self._listening = False
        self._listen_thread: Optional[threading.Thread] = None
        
        try:
            # Initialize Redis connection
            self.redis_client = redis.Redis(
                host=host,
                port=port,
                password=password,
                db=db,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                **kwargs
            )
            
            # Test connection
            self.redis_client.ping()
            logger.info(f"Redis watcher connected to {host}:{port}, database {db}")
            
        except Exception as e:
            logger.error(f"Failed to connect to Redis for watcher: {e}")
            raise

    def set_update_callback(self, callback: Callable) -> None:
        """
        Set the callback function to be called when a policy update is received.

        Args:
            callback (Callable): Function to call when policies are updated.
        """
        self.update_callback = callback
        self._start_listening()

    def update(self, *args: Any) -> None:
        """
        Notify other instances that policies have been updated.

        This method publishes a policy update message to the Redis channel,
        which will trigger policy reloads on all listening instances.

        Args:
            *args: Additional arguments (for interface compatibility).
        """
        if not self.redis_client:
            logger.warning("Redis client not available, cannot publish policy update")
            return

        try:
            message = {
                "timestamp": time.time(),
                "action": "policy_updated",
                "source": "casbin_enforcer"
            }
            
            result = self.redis_client.publish(self.channel, json.dumps(message))
            logger.debug(f"Published policy update to {result} subscribers")
            
        except Exception as e:
            logger.error(f"Failed to publish policy update: {e}")

    def _start_listening(self) -> None:
        """
        Start listening for policy update messages on the Redis channel.
        """
        if self._listening or not self.redis_client:
            return

        try:
            self.pubsub = self.redis_client.pubsub()
            self.pubsub.subscribe(self.channel)
            self._listening = True
            
            # Start listener thread
            self._listen_thread = threading.Thread(
                target=self._listen_for_updates,
                daemon=True,
                name="casbin-redis-watcher"
            )
            self._listen_thread.start()
            logger.info(f"Started listening for policy updates on channel '{self.channel}'")
            
        except Exception as e:
            logger.error(f"Failed to start Redis listener: {e}")
            self._listening = False

    def _listen_for_updates(self) -> None:
        """
        Listen for policy update messages and trigger the callback.
        
        This method runs in a separate thread and continuously listens for
        messages on the Redis pub/sub channel.
        """
        if not self.pubsub:
            return

        try:
            for message in self.pubsub.listen():
                if not self._listening:
                    break
                    
                if message["type"] == "message":
                    try:
                        data = json.loads(message["data"])
                        if data.get("action") == "policy_updated":
                            logger.debug("Received policy update notification")
                            if self.update_callback:
                                self.update_callback()
                                
                    except (json.JSONDecodeError, KeyError) as e:
                        logger.warning(f"Invalid policy update message: {e}")
                        
        except Exception as e:
            logger.error(f"Error in Redis listener: {e}")
        finally:
            self._listening = False

    def close(self) -> None:
        """
        Close the Redis watcher and clean up resources.
        """
        logger.info("Closing Redis watcher")
        
        # Stop listening
        self._listening = False
        
        # Close pubsub connection
        if self.pubsub:
            try:
                self.pubsub.unsubscribe(self.channel)
                self.pubsub.close()
            except Exception as e:
                logger.warning(f"Error closing pubsub: {e}")
            finally:
                self.pubsub = None
        
        # Wait for listener thread to finish
        if self._listen_thread and self._listen_thread.is_alive():
            self._listen_thread.join(timeout=5)
            if self._listen_thread.is_alive():
                logger.warning("Redis listener thread did not stop gracefully")
        
        # Close Redis connection
        if self.redis_client:
            try:
                self.redis_client.close()
            except Exception as e:
                logger.warning(f"Error closing Redis connection: {e}")
            finally:
                self.redis_client = None

    def __del__(self):
        """Cleanup on object destruction."""
        try:
            self.close()
        except Exception:
            pass  # Ignore errors during cleanup 