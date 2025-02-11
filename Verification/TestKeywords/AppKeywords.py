from robot.api.deco import keyword, library
from robot.libraries.BuiltIn import BuiltIn
import shutil
import zipfile
import pyautogui
import subprocess
import pyotp
from jsonrpcclient import request
import requests
import time 
import sys
import os
from dotenv import load_dotenv
from robot.api import logger

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Resources')))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "sessionServer.config.settings")

from BaseLib import BaseLib
from Verification.Config.config import Config, EMAIL, USERNAME, DOMAIN
from sessionServer.userauth.two_factor import TwoFactor

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))

logger.info(f"{os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))}")

from Client.main import main


@library()
class AppKeywords(BaseLib):
    def __init__(self):
        """
        Initializes the AppKeywords library.

        Attributes:
            app_process (Optional[subprocess.Popen]): Holds the application process instance.
            session_server_is_runing (bool): Indicates whether the session server is running.
        """
        logger.info("Initializing AppKeywords library.")
        self.app_process = None
        self.session_server_is_runing = False

    @keyword("Set Env")
    def set_env(self) -> None:
        """
        Configures the environment for the session server and client.
        """
        logger.info("Setting environment variables for session server and client.")
        Config.set_session_server_env()
        Config.set_client_env()
        time.sleep(2)
     
    @keyword("Set Client Env")   
    def set_client_env(self) -> None:
        """
        Configures the environment for the client.
        """
        logger.info("Setting environment variables for  client.")
        Config.set_client_env()
        time.sleep(2)
      
    @keyword("Change Server Domain")  
    def change_session_server_domain(self, domain:str) -> None:
        """
        Change session server name for test connection.

        Args:
            domain (str): domain name.
        """
        Config.change_session_server_domain(domain)
        logger.info(f"DOMAIN:{Config.DOMAIN}")
 
    @keyword("Start Session Server")
    def start_session_server(self,docker_compose_path:str) -> None:
        """
        Starts the session server using Docker Compose.

        Args:
            docker_compose_path (str): Path to the Docker Compose file.

        Raises:
            RuntimeError: If Docker Compose commands fail.
        """
        original_dir = os.getcwd() 
        logger.info(f"orginal_dir: {original_dir}")
        try:
            os.chdir(self._relative_path(docker_compose_path))

            logger.info("Starting Docker Compose with build.")
            subprocess.run(
                ["docker-compose", "up", "--build", "-d"],
                check=True
            )
            
            time.sleep(30)
            
            logger.info("Setting client secret in the session server.")
            command = [
                "docker", "exec", "my_apache", "python", "manage.py", "set_client_secret", USERNAME
            ]
        
            subprocess.run(
                command,
                check=True
            )
            
            time.sleep(5)
            
            self.session_server_is_runing = True
                
        except subprocess.CalledProcessError as e:
            logger.error(f"Docker-compose command failed: {e}")
            raise RuntimeError(f"Docker-compose command failed: {e}")
        except Exception as e:
            logger.error(f"Error occurred: {e}")
            raise RuntimeError(f"Error occurred: {e}")
        finally:
            os.chdir(original_dir)
            
    @keyword("Stop Session Server")
    def stop_session_server(self,docker_compose_path:str) -> None: 
        """
        Stops the session server using Docker Compose.

        Args:
            docker_compose_path (str): Path to the Docker Compose file.

        Raises:
            RuntimeError: If containers are still running after stopping the server.
        """
        original_dir = os.getcwd()
        logger.info(f"Stopping session server, original directory: {original_dir}")
        if not self.session_server_is_runing:
            try:
                os.chdir(self._relative_path(docker_compose_path))

                logger.info("Stopping Docker Compose.")
                subprocess.run(["docker-compose", "down"], check=True)

                result = subprocess.run(
                    ["docker-compose", "ps"],
                    capture_output=True,
                    text=True,
                    check=True
                )
                logger.info(f"Docker Compose status output: {result.stdout}")
                running_containers = [
                    line for line in result.stdout.splitlines()
                    if "Up" in line or "Exited" in line or "Exit" in line
                ]

                if running_containers:
                    logger.error(f"Still running containers: {running_containers}")
                    raise RuntimeError("Some containers are still running!")
                
                self.session_server_is_runing = False
            finally:
                os.chdir(original_dir)      
        
    @keyword("Start Application")
    def start_application(self) -> None:
        """
        Starts the client application.
        """
        logger.info("Starting the client application.")
        api_path = os.path.join(BASE_DIR,"Client","main.py")
        args = ["python3", api_path, "--test", "true"]
        
        env_path = Config.env_client_file_path
        if os.path.exists(env_path):
            logger.info(f"Loading environment variables from {env_path}")
        load_dotenv(env_path, override=True)

        self.app_process = subprocess.Popen(
            args,
            shell=True,
            env=os.environ
        )
        time.sleep(5)
   
    @keyword("Stop Application")
    def stop_application(self) -> None:
        """
        Stops the client application if it is running.
        """
        if self.app_process:
            logger.info("Stopping the client application.")
            self.app_process.terminate()
            self.app_process.wait()
            
        self.app_process = None
    
    @keyword("Check If App Running")
    def check_if_app_running(self) -> bool:
        """
        Checks whether the client application is running.

        Returns:
            bool: True if the application is running, otherwise raises AssertionError.

        Raises:
            AssertionError: If the application is not running.
        """
        if self.app_process:
            logger.info("Application is running.")
            self._attach_screenshot_to_report_base64()
            return True 
        else:
            logger.error("Application is not running.")
            raise AssertionError("Application is not running.")
        
    @keyword("Set Text")  
    def set_text(self, field_name:str, text_value:str) -> None:
        """
        Sets text in the specified UI field using an API.

        Args:
            field_name (str): The name of the UI field.
            text_value (str): The text to set.

        Raises:
            AssertionError: If the operation fails.
        """
        logger.info(f"Setting text for field '{field_name}' with value '{text_value}'.")

        response = requests.post(
            "http://localhost:9081/api", json=request(method="set_text", params={"field_name": field_name, "text_value": text_value},id=1)
        )

        logger.info(f"Response: {response.json()}")
        if "result" not in response.json():
            if "error" in response.json():
                BuiltIn().fail(f"Set {text_value} Failed with error: {response.json()["error"]} ")
            else:
                BuiltIn().fail(f"Set {text_value} Failed with unexpected behavior: {response.json()} ")
                
        logger.info("Set text executed successfully")
        
    @keyword("Click Object")     
    def click_object(self, item_name:str) ->None:
        """
        Simulates a mouse click on a specified object by obtaining its coordinates via an API call.

        Args:
            item_name (str): The name of the object to be clicked.
        """
        logger.info(f"Click Object with: item_name: {item_name}")
        
        response = requests.post(
            "http://localhost:9081/api", json=request(method="get_coordinates", params={"object_name": item_name},id=1)
        )

        logger.info(f"Response: {response.json()}")
        if "result" not in response.json():
            if "error" in response.json():
                BuiltIn().fail(f"Click object {item_name} Failed with error: {response.json()["error"]["message"]}:{response.json()["error"]["data"]} ")
            
        if "global_x" in response.json()["result"] and "global_y" in response.json()["result"]:
            if item_name == "popupButton":
                x = float(response.json()["result"]["global_x"]) + float(response.json()["result"]["width"])/2
                y = float(response.json()["result"]["global_y"]) + float(response.json()["result"]["height"])
            else:
                x = float(response.json()["result"]["global_x"]) + float(response.json()["result"]["width"])/2
                y = float(response.json()["result"]["global_y"]) + float(response.json()["result"]["height"])/2
            logger.info(f"the mouse will be moved into position pos(x.y):({x}.{y})")
            pyautogui.moveTo(x=x, y=y, duration=1)
            pyautogui.click()
            
      
    @keyword("Type Textfield")       
    def type_textfield(self,text: str,field_name:str) ->None:
        """
        Types text into a specified text field and verifies the input using an API call.

        Args:
            text (str): The text to be entered.
            field_name (str): The name of the text field.
        """
        logger.info(f"Typing text '{text}' into field '{field_name}'")
        pyautogui.typewrite(text)
        
        response = requests.post(
            "http://localhost:9081/api", json=request(method="get_text_from_field", params={"field_name": field_name},id=1)
        )
        logger.info(f"Response: {response.json()}")
        if "result" not in response.json():
            if "error" in response.json():
                BuiltIn().fail(f"type text: {text} Failed with error: {response.json()["error"]["message"]}:{response.json()["error"]["data"]} ")
                
        current_text = response.json()["result"]["text"]  
        if current_text != text:
            BuiltIn().fail(f"Text mismatch: expected '{text}', got '{current_text}'")
    
    @keyword("Get Tokens") 
    def get_tokens(self) -> list:
        """
        Retrieves tokens via an API call.

        Returns:
            list: A list of tokens retrieved from the API response.
        """
        logger.info("Getting tokens")
        response = requests.post(
            "http://localhost:9081/api", json=request(method="get_tokens", params={},id=1)
        )
        
        logger.info(f"Response: {response.json()}")
        if "result" not in response.json():
            if "error" in response.json():
                BuiltIn().fail(f"Get tokens failed with error: {response.json()['error']['message']}:{response.json()['error']['data']}")
        
        logger.info(f"{type(response.json()["result"])}")
        return  response.json()["result"]      
    
    @keyword("If Object Visible")       
    def if_object_visible(self, object_name:str) -> None:
        """
        Checks if a specified object is visible via an API call.

        Args:
            object_name (str): The name of the object to check visibility for.

        """
        logger.info(f"Checking visibility of object: {object_name}")
        
        response = requests.post(
            "http://localhost:9081/api", json=request(method="is_object_visible", params={"object_name": object_name},id=1)
        )
        
        logger.info(f"Response: {response.json()}")
        if "result" not in response.json():
            if "error" in response.json():
                BuiltIn().fail(f"Visibility check failed with error: {response.json()['error']['message']}:{response.json()['error']['data']}")
                
                   
    @keyword("Check Popup")       
    def check_popup(self, object_name:str, expected_message:str) ->None:
        """
        Verifies a popup's message via an API call.

        Args:
            object_name (str): The name of the popup object.
            expected_message (str): The expected message in the popup.
        """
        logger.info(f"Checking popup with object: {object_name} and expected message: {expected_message}")
        
        response = requests.post(
            "http://localhost:9081/api", json=request(method="is_popup_visible", params={"object_name": object_name},id=1)
        )
        
        if "result" not in response.json():
            if "error" in response.json():
                BuiltIn().fail(f"Popup with error: {response.json()["error"]["message"]}:{response.json()["error"]["data"]} ")
                
        self._attach_screenshot_to_report_base64()   
           
        message = response.json()["result"]["message"]
        
        if message != expected_message:
            BuiltIn().fail(f"Message mismatch: expected '{expected_message}', got '{message}'") 
            
    @keyword("Get Two Factore Code")         
    def get_2fa_code(self) -> str:
        """
        Generates a two-factor authentication (2FA) code using TOTP.

        Returns:
            str: The generated 2FA code.
        """
        secret_key = TwoFactor.generate_secret_key(EMAIL, USERNAME)
        logger.debug(f"Client secret key: {secret_key}")
        totp = pyotp.TOTP(secret_key) 
        return totp.now()
     
    @keyword("Clear Textfield")   
    def clear_textfield(self) -> None:
        """
        Clears the content of the current text field using a keyboard shortcut.
        """
        logger.info("Clearing text field")
        pyautogui.hotkey('ctrl', 'a')
        pyautogui.press('backspace')
        
    @keyword("Collect And Archive Logs")
    def collect_and_archive_logs(self) -> None:
        """
        Collects log files, archives them into a zip file, and clears the original logs.
        """
        logger.info("Collecting and archiving logs")
        
        temp_dir = os.path.join(BASE_DIR,"Verification","logs", "temp_logs")
        zip_file = os.path.join(BASE_DIR,"Verification","logs", "Logs_Archive.zip")
        
        log_files = [
            os.path.join(BASE_DIR, "sessionServer", "tests", "logs", "secret.log"),
            os.path.join(BASE_DIR, "sessionServer", "logs", "django.log"),
            os.path.join(BASE_DIR, "sessionServer", "apache2", "logs", "error.log"),
            os.path.join(BASE_DIR, "Client", "logs", "logs.log"),
        ]
        
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)
            
        for log_file in log_files:
            if os.path.exists(log_file):
                logger.info(f"path exist:{log_file}")
                shutil.copy(log_file, temp_dir)
            else:
                print(f"Warning: Log file not found: {log_file}")
                
        with zipfile.ZipFile(zip_file, 'w') as zipf:
            for root, _, files in os.walk(temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zipf.write(file_path, arcname)
        
        for log_file in log_files:
            if os.path.exists(log_file):
                with open(log_file, 'w') as file:
                    file.write("")
                    
        shutil.rmtree(temp_dir) 