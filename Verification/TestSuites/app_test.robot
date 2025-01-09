*** Settings ***
Documentation     This test suite verifies the login functionality, 
...               including valid and invalid scenarios, 2FA handling, and token management.
Metadata          Zip Logs File    [file:///D:/MicrosoftVSCode/Monitoring/Session_Server/Verification/logs/Logs_Archive.zip|Download Logs Archive]
Library           ../TestKeywords/AppKeywords.py
Variables         ../Resources/TestsData.py

Suite Setup    Suite Setup
Suite Teardown    Suite Teardown

Test Setup      Test Setup
Test Teardown    Test Teardown

*** Keywords ***
Suite Setup
    [Documentation]    Prepares the environment for test execution by setting required variables and starting the session server.
    Set Env
    Start Session Server    /sessionServer/

Suite Teardown
    [Documentation]    Cleans up after all tests by collecting logs and stopping the session server.
    Collect And Archive Logs
    Stop Session Server    /sessionServer/

Test Setup
    [Documentation]     Starts the application before each test to ensure a clean slate.
    Start Application

Test Teardown
    [Documentation]    Closes the application and stops it after each test.   
    Click Object    ${CLOSE_BUTTON}
    Stop Application

Stop Session Server And Start App
    [Documentation]    Stop session server and start App to simulate connection failed
    Stop Session Server    /sessionServer/
    Start Application

*** Test Cases ***
Test Open and Close App
    [Tags]  Smoke Test
    [Documentation]    Validates that the application can start and stop without issues.
    Check If App Running

Test Remember Username
    [Tags]  System Test
    [Documentation]    Tests the "Remember Me" functionality by verifying the username persists across sessions.
    Set Text    ${USERNAME_TEXT_FIELD}    Czeslaw
    Click Object    ${REMEMBER_ME_SWITCH}
    Click Object     ${CLOSE_BUTTON}
    Start Application
    Type Textfield  Czeslaw     ${USERNAME_TEXT_FIELD}
    Click Object    ${REMEMBER_ME_SWITCH}
    Type Textfield  ${EMPTY}     ${USERNAME_TEXT_FIELD}

Test Popup Invalid Username and password
    [Tags]  System Test
    [Documentation]     Verifies that the correct error message appears when both username and password are missing.
    Click Object    ${LOGIN_BUTTON}
    Check Popup     ${POPUP_WINDOW}   Please enter both username and password.
    Click Object    ${ERROR_POPUP_BUTTON}  

Test Popup Invalid Username
    [Tags]  System Test
    [Documentation]    Verifies that an appropriate error message is shown when the username is missing.
    Set Text    ${PASSWORD_TEXT_FIELD}  ${PASSWORD}
    Click Object    ${LOGIN_BUTTON}
    Check Popup     ${POPUP_WINDOW}   Please enter a username.
    Click Object    ${ERROR_POPUP_BUTTON}

Test Invalide Two Factore Code
    [Tags]  System Test
    [Documentation]    Ensures that an invalid 2FA code generates the correct error message.
    Set Text    ${USERNAME_TEXT_FIELD}  ${USERNAME}
    Set Text    ${PASSWORD_TEXT_FIELD}  ${PASSWORD}
    Click Object    ${LOGIN_BUTTON}
    Set Text    ${TWO_FACTORE_CODE_TEXT_FIELD}  abc
    Click Object    ${TOTP_BUTTON}
    Check Popup     ${POPUP_WINDOW}   2FA code must consist of exactly 6 digits.
    Click Object    ${ERROR_POPUP_BUTTON}

Test Valid Code
    [Tags]  System Test
    [Documentation]    Validates login with correct 2FA code.
    Set Text    ${USERNAME_TEXT_FIELD}  ${USERNAME}
    Set Text    ${PASSWORD_TEXT_FIELD}  ${PASSWORD}
    Click Object    ${LOGIN_BUTTON}
    ${CODE}=    Get Two Factore Code
    Set Text    ${TWO_FACTORE_CODE_TEXT_FIELD}  ${CODE}
    Type Textfield  ${CODE}     ${TWO_FACTORE_CODE_TEXT_FIELD}

Test Login And Logout Successful 
    [Tags]  System Test
    [Documentation]    Confirms successful login, token retrieval, and proper token clearance after logout.
    Set Text    ${USERNAME_TEXT_FIELD}  ${USERNAME}
    Set Text    ${PASSWORD_TEXT_FIELD}  ${PASSWORD}
    Click Object    ${LOGIN_BUTTON}
    ${CODE}=    Get Two Factore Code
    Set Text    ${TWO_FACTORE_CODE_TEXT_FIELD}  ${CODE}
    Type Textfield  ${CODE}     ${TWO_FACTORE_CODE_TEXT_FIELD}
    Click Object    ${TOTP_BUTTON}
    Sleep   10
    If Object Visible   ${APP_WINDOW}
    ${current_tokens}=      Get Tokens
    Should Not Be Empty   ${current_tokens['access_tokens']}
    Click Object    ${APP_CLOSE_BUTTON}
    Sleep   10
    ${tokens_after_logout}=      Get Tokens
    Should Be Empty     ${tokens_after_logout['access_tokens']}

Test Refresh Token 
    [Tags]  System Test
    [Documentation]    Validates the token refresh mechanism and ensures old tokens are replaced.
    Set Text    ${USERNAME_TEXT_FIELD}  ${USERNAME}
    Set Text    ${PASSWORD_TEXT_FIELD}  ${PASSWORD}
    Click Object    ${LOGIN_BUTTON}
    ${CODE}=    Get Two Factore Code
    Set Text    ${TWO_FACTORE_CODE_TEXT_FIELD}  ${CODE}
    Type Textfield  ${CODE}     ${TWO_FACTORE_CODE_TEXT_FIELD}
    Click Object    ${TOTP_BUTTON}
    Sleep   10
    If Object Visible   ${APP_WINDOW}
    ${current_tokens}=      Get Tokens
    Should Not Be Empty   ${current_tokens['access_tokens']}
    Sleep    90
    ${new_tokens}=      Get Tokens
    Should Not Be Equal    ${current_tokens['access_tokens']}    ${new_tokens['access_tokens']}
    Click Object    ${APP_CLOSE_BUTTON}
    Sleep   10
    ${tokens_after_logout}=      Get Tokens
    Should Be Empty     ${tokens_after_logout['access_tokens']}

Test Login Failed
    [Tags]  System Test
    [Setup]     Stop Session Server And Start App
    [Documentation]    Simulates a failed login scenario due to server connection issues and verifies error handling.
    Set Text    ${USERNAME_TEXT_FIELD}  ${USERNAME}
    Set Text    ${PASSWORD_TEXT_FIELD}  ${PASSWORD}
    Type Textfield  ${USERNAME}     ${USERNAME_TEXT_FIELD}
    Click Object    ${LOGIN_BUTTON}
    ${CODE}=    Get Two Factore Code
    Set Text    ${TWO_FACTORE_CODE_TEXT_FIELD}  ${CODE}
    Type Textfield  ${CODE}     ${TWO_FACTORE_CODE_TEXT_FIELD}
    Click Object    ${TOTP_BUTTON}
    Sleep   5
    Check Popup     ${POPUP_WINDOW}   Applications have faced a critical issue:Cannot connect to host sessionid:8080 ssl:default [Komputer zdalny odrzucił połączenie sieciowe],Please contact the administrator
    Click Object    ${ERROR_POPUP_BUTTON}



