from jsonrpcserver import method, Result, Success, Error, async_dispatch
from PyQt6.QtCore import QObject,QPointF,QPoint
from PyQt6.QtQuick import QQuickItem
from PyQt6.QtGui import QGuiApplication

import json
import asyncio
import logging
from aiohttp import web
from aiohttp.web_request import Request
from aiohttp.web_response import Response
from qasync import asyncClose


logger = logging.getLogger(__name__)

class TestApi:
    """
    TestApi provides JSON-RPC methods for interacting with a UI using Qt and PyQt6.
    """
    engine = None
    user_manager = None

    def __init__(self, engine, user_manager):
        """
        Initialize the TestApi class.

        Args:
            engine: The Qt engine instance to interact with.
            user_manager: The user manager instance for managing tokens.
        """
        self.__class__.engine = engine 
        self.__class__.user_manager = user_manager
        self.app = web.Application()
        self.runner = None
        
    @staticmethod
    @method
    async def get_tokens() -> Result:
        """
        Fetch all user tokens.

        Returns:
            Success: List of tokens if successful.
            Error: Error message if fetching tokens fails.
        """
        logger.info("Fetching all tokens.")
        try:
            tokens = await TestApi.user_manager.get_all_tokens()
        except Exception as e:
            logger.error(f"Unexpected error while fetching tokens: {e}")
            return Error(code = -32000,message="Unexpected error",data={"error": f"Unexpected error: {e} "})
        logger.info(f"Fetched tokens: {tokens}")
        return Success(tokens)
    
    @staticmethod
    @method
    async def is_object_visible(object_name: str) -> Result:
        """
        Check if a specific object is visible in the UI.

        Args:
            object_name (str): The name of the object to check.

        Returns:
            Success: Status indicating visibility if the object is found and visible.
            Error: Error message if the object is not found or not visible.
        """
        logger.info(f"Checking visibility for object: {object_name}")
        root = TestApi.engine.rootObjects()[0]
        popup = root.findChild(QObject, object_name)
        logger.info(f"Found popup: {popup}")
        
        if not popup:
            logger.error(f"{object_name} not found")
            return Error(code = -32000,message="Unexpected error",data={"error": f"{object_name} not found"})
        
        if not popup.property("visible"):
            logger.error(f"{object_name} window is not visible")
            return Error(code = -32000,message="Unexpected error",data={"error": f" {object_name} window is not visible"})
        
        return Success({"status": 200})
        
    @staticmethod
    @method
    async def is_popup_visible(object_name: str) -> Result:
        """
        Verify if a popup is visible and retrieve its message.

        Args:
            object_name (str): The name of the popup to check.

        Returns:
            Success: The message from the popup if it is visible.
            Error: Error message if the popup is not found or not visible.
        """
        logger.info(f"Checking visibility for popup: {object_name}")
        root = TestApi.engine.rootObjects()[0]
        popup = root.findChild(QObject, object_name)
        
        if not popup:
            logger.error(f"Popup {object_name} not found")
            return Error(code = -32000,message="Unexpected error",data={"error": f"Popup {object_name} not found"})
        
        if not popup.property("visible"):
            logger.error(f"Popup {object_name} window is not visible")
            return Error(code = -32000,message="Unexpected error",data={"error": f"Popup {object_name} window is not visible"})
        
        actual_message = popup.property("message")
        logger.info(f"Popup message: {actual_message}")
        
        return Success({"message": actual_message})
        
    @staticmethod
    @method
    async def get_coordinates(object_name: str) -> Result:
        """
        Retrieve coordinates and dimensions of an object.

        Args:
            object_name (str): The name of the object.

        Returns:
            Success: A dictionary with coordinates and dimensions.
            Error: Error message if the object is not found.
        """
        logger.info(f"Retrieving coordinates for object: {object_name}")
        root = TestApi.engine.rootObjects()[0]
        obiect = root.findChild(QObject, object_name)
        
        logger.info(f"{obiect.objectName()}")
        logger.info(f"{obiect.parent().objectName()}")
        logger.info(f"Object window: {obiect.window().objectName()}")

        if not obiect:
            logger.error(f"Button '{object_name}' not found")
            return Error(code = -32000,message="Unexpected error",data={"error": f"Button '{object_name}' not found"})
        
        if isinstance(obiect, QQuickItem):

            logger.info(f" Object instance is {type(obiect)}")
            local_pos = obiect.mapToScene(QPointF(0, 0)).toPoint()
            global_pos = obiect.window().mapToGlobal(local_pos)
            
            logger.info(f"Local position: {local_pos}, Global position: {global_pos}")
            
        for screen in QGuiApplication.screens():
            logger.info(f"Screen: {screen.name()}, Geometry: {screen.geometry()}, Scaling: {screen.devicePixelRatio()}")
        screens = []    
        current_screen = QGuiApplication.screenAt(global_pos)
        
        for screen in QGuiApplication.screens():
            logger.info(f"Screen: {screen.name()}, Geometry: {screen.geometry()}, Scaling: {screen.devicePixelRatio()}")
            screens.append(screen)
            
        if screen:
            scaling_factor = screen.devicePixelRatio()
            screen_geometry = screen.geometry()
            if screen_geometry.topLeft().x() == 0 and screen_geometry.topLeft().y() == 0:
                logger.info(f"global_pos:{global_pos}/screen_geometry.topLeft():({screen_geometry.topLeft().x()}.{screen_geometry.topLeft().y()})/scaling_factor:{scaling_factor}")
                adjusted_pos = (global_pos ) * scaling_factor
                logger.info(f"Adjusted position {screen.name()}: {adjusted_pos.x()}.{adjusted_pos.y()}")
            else:
                logger.info(f"global_pos:{global_pos}/screen_geometry.topLeft():({screen_geometry.topLeft().x()}.{screen_geometry.topLeft().y()})/scaling_factor:{scaling_factor}")
                adjusted_pos = (global_pos ) * scaling_factor
                screen_index = screens.index(screen)
                if screen_index >= 1:
                    previos_screen = screens[screen_index-1]
                    adjusted_pos = (global_pos) * previos_screen.devicePixelRatio()
            
        return Success({
            "x": obiect.property("x"),
            "y": obiect.property("y"),
            "width": obiect.property("width"),
            "height": obiect.property("height"),
            "local_x":local_pos.x(),
            "local_y":local_pos.y(),
            "global_x":adjusted_pos.x(),
            "global_y":adjusted_pos.y(),
            })

    @staticmethod
    @method
    async def set_text(field_name: str, text_value: str) -> Result:
        """
        Set the text of a specific field.

        Args:
            field_name (str): The name of the field.
            text_value (str): The text to set.

        Returns:
            Success: Status if the text is successfully set.
            Error: Error message if the field is not found.
        """
        logger.info(f"Setting text for field '{field_name}' to '{text_value}'.")
        root = TestApi.engine.rootObjects()[0]
        text_field = root.findChild(QObject, field_name)
        
        if not text_field:
            logger.error(f"Field '{field_name}' not found")
            return Error(code = -32000,message="Unexpected error",data={"error":f"Field '{field_name}' not found"})
        text_field.setProperty("text", text_value)
        logger.info(f"Text set for field '{field_name}'.")
        
        return Success({"status": 200})
    
    @staticmethod
    @method
    async def get_text_from_field( field_name: str) -> str:
        """
        Retrieve text from a specific field.

        Args:
            field_name (str): The name of the field.

        Returns:
            Success: Text from the field if found.
            Error: Error message if the field is not found or has no text property.
        """
        logger.info(f"Fetching text from field '{field_name}'.")
        root = TestApi.engine.rootObjects()[0]
        text_field = root.findChild(QObject, field_name)
        if not text_field:
            logger.error(f"Field '{field_name}' not found")
            return Error(code = -32000,message="Unexpected error",data={"error":f"Field '{field_name}' not found"})
        
        if isinstance(text_field, QQuickItem):
            text = text_field.property("text")
        
        if text is not None:
                return Success({"text":text})
            
        logger.error(f"Field '{field_name}' does not have a 'text' property.")
        return Error(code = -32000,message="Unexpected error",data={"error":f"Obiekt '{field_name}' does not have the text property 'text'"})

    async def handle(self, request: Request) -> Response:
        """
        Handle incoming JSON-RPC requests.

        Args:
            request (Request): The incoming HTTP request containing JSON-RPC data.

        Returns:
            Response: An HTTP response object.
                - Status 200: If the request is successfully processed and contains a "result".
                - Status 500: If an error occurs or the response contains an "error".
                - Status 204: If no content is returned in the response.
        """
        request = await request.text()
        logger.info(f"Received request: {request}")
        response = await async_dispatch(request)
        try:
            response_dict = json.loads(response)
        except json.JSONDecodeError:
            logger.error("Invalid JSON-RPC response")
            return web.Response(status=500, text="Invalid JSON-RPC response")
        if "result" in response_dict:
            return web.json_response(response_dict, status=200)
        elif "error" in response_dict:
            return web.json_response(response_dict, status=500)
        return web.Response(status=204)

    async def start_server(self) -> None:
        """
        Start the JSON-RPC server using AioHTTP.

        This method sets up the server to listen for JSON-RPC requests on the
        `/api` endpoint. It binds the server to `localhost` at port `9081`.

        Returns:
            None
        """
        logger.info("Configuring the JSON-RPC server...")
        self.app.router.add_post("/api", self.handle)
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "localhost", 9081)
        logger.info("Starting JSON-RPC server on http://localhost:9081/api")
        await site.start()

    @asyncClose
    async def shutdown(self) -> None:
        """
        Shutdown the JSON-RPC server.

        This method cleans up the server resources, including shutting down
        the application runner.

        Returns:
            None
        """
        logger.info("Test API Shutdown initiated.")
        if self.runner:
            logger.info("Shutting down the server...")
            await self.runner.cleanup()
            logger.info("Server shutdown complete.")
