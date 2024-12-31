from PyQt6.QtCore import QObject
from app.signals.signal_menager import SignalManager

import asyncio
from qasync import asyncSlot,asyncClose
import logging

logger = logging.getLogger(__name__)

class CentralQueueManager(QObject, SignalManager):
    """
    Manages a central queue of tasks with priority-based execution and signal management.
    """

    def __init__(self, parent: QObject = None) -> None:
        """
        Initializes the CentralQueueManager.
        
        Args:
            parent (QObject, optional): The parent QObject. Defaults to None.
        """
        super().__init__(parent)
        logger.debug("Initializing CentralQueueManager...")
        
        self.event_loop = asyncio.get_running_loop()
        self.tasks = asyncio.PriorityQueue()
        logger.debug("Priority queue initialized.")
        logger.debug(f"event_loop  {self.event_loop}")
        
    def handle_exception(self, exception: Exception, event_type: str, payload: dict, module: str) -> None:
        """
        Handles exceptions that occur during task processing.

        Args:
            exception (Exception): The exception that occurred.
            event_type (str): The type of the event being processed.
            payload (dict): The data associated with the event.
            module (str): The module where the exception occurred.
        """
        logger.error(f"Exception occurred while processing event '{event_type}': {exception}", exc_info=True)
        logger.debug(f"Payload that caused the error: {payload}")
        self.handle_exception_event.emit(exception,event_type,payload,module)
        
    async def start(self) -> None:
        """
        Starts processing tasks in the shared event loop.
        """
        logger.debug("Starting task processing coroutine.")
        await self._process_tasks()
    
    async def _process_tasks(self) -> None:
        """
        Continuously processes tasks from the priority queue and emits appropriate signals.
        """
        logger.debug("Task processing loop started.")
        while True:
            try:
                logger.debug("Waiting for the next task...")
                priority, event_type, payload , module = await self.tasks.get()
                logger.info(f"Processing task: priority={priority}, event_type={event_type}, payload={payload}")

                try:
                    logger.info("Attempt to execute event")
                    self.emit_event(event_type,payload)  
                except Exception as e:
                    logger.error(f"Exception for event process: {e} ")
                    self.handle_exception(e, event_type, payload, module)
                finally:
                    logger.info(f"Finally for event process:")
                    if not self.tasks.empty():
                        self.tasks.task_done()
                
            except asyncio.CancelledError:
                logger.info("Task processing was cancelled.")
                break 

            except Exception as e:
                logger.error(f"Unexpected error in task processing loop: {e}", exc_info=True)
                break
                
    @asyncSlot(int,str,dict,str)
    async def add_task(self, priority: int, event_type: str, payload: dict, module: str) -> None:
        """
        Adds a new task to the priority queue.

        Args:
            priority (int): The priority of the task (lower value indicates higher priority).
            event_type (str): The type of the event (e.g., "login", "refresh_token").
            payload (dict): Additional data associated with the event.
            module (str): The name of the module associated with the task.
        """
        logger.debug(f"Adding task to queue: priority={priority}, event_type={event_type}, payload={payload}, module={module}")
        try:
            if self.event_loop.is_closed():
                raise RuntimeError("Event loop is closed. Cannot add tasks.")
             
            await self.tasks.put((priority, event_type, payload, module))
            
            logger.info(f"Task successfully added to the queue.{self.tasks.qsize()}")
        except Exception as e:
            logger.error(f"Failed to add task to queue: {str(e)}", exc_info=True)
            self.handle_exception(e, event_type, payload, module)
        
    def emit_event(self, event_type: str, payload: dict) -> None:
        """
        Handles emitting signals based on the event type.

        Args:
            event_type (str): The type of the event to emit.
            payload (dict): The data associated with the event.
        """
        logger.debug(f"Emitting event: {event_type} with payload: {payload}")
        
        event_map = {
            "login": lambda: (self.send_login_event.emit(payload),self.set_secret_key.emit(payload["code"],payload["password"])),
            "handle_login": lambda: self.handle_login_event.emit(payload),
            "login_failed": lambda: (self.login_failed_event.emit(payload["error"])),
            "login_success": lambda: self.login_success_event.emit(),
            "refresh_token": lambda: self.send_refresh_token_event.emit(payload),
            "handle_refresh_token": lambda: self.handle_refresh_token_event.emit(payload),
            "logout": lambda: self.logout_get_token_event.emit(),
            "send_logout": lambda: self.send_logout_event.emit(payload["access_token"]),
            "handle_logout": lambda: (self.handle_logout_event.emit(payload)),
            "logout_success": lambda:self.logout_success_event.emit(),
        }
        
        try:
            if event_type not in event_map:
                logger.warning(f"Unknown event type: {event_type}")
                raise ValueError(f"Unknown event type: {event_type}")

            if not isinstance(payload, dict):
                raise ValueError(f"Payload must be a dictionary for event: {event_type}")
            
            event_map[event_type]()
            
        except Exception as e:
            logger.error(f"Error processing task: {str(e)}", exc_info=True)
        finally:
            if event_type in ["login_failed", "handle_logout"]:
                self.clear_tasks()
            logger.debug("Task marked as done.")

            
    def clear_tasks(self) -> None:
        """
        Clears all tasks in the priority queue for this manager.
        """
        logger.info("Clearing CentralQueueManager tasks ...")

        while not self.tasks.empty():
            try:
                removed_task = self.tasks.get_nowait()
                logger.debug(f"Removed task: {removed_task}")
            except asyncio.QueueEmpty:
                logger.warning("Tried to clear an empty queue.")
                raise
    
    logger.info("Priority queue cleared.")
   
    @asyncClose   
    async def stop(self) -> None:
        """
        Stops the CentralQueueManager and cancels pending tasks.
        """
        logger.info("Stopping CentralQueueManager task in event loop...")
        pending_tasks = asyncio.all_tasks(self.event_loop)
        for task in pending_tasks:
            if task is not asyncio.current_task():
                try:
                    coro_name = task.get_coro().__qualname__
                    logger.info(f"task: {coro_name}")
                    if "CentralQueueManager.stop" not in coro_name and "CentralQueueManager" in coro_name:
                        logger.info(f"Cancelling task: {coro_name}")
                        task.cancel()
                except asyncio.CancelledError:
                    logger.warning(f"Task {task} was already cancelled.")
                except Exception as e:
                    logger.error(f"Error cancelling task {task}: {e}")

        logger.info("All tasks have been cancelled.")


        