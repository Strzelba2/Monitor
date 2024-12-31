import QtQuick 2.15
import QtQuick.Controls.Fusion

// The main login window
Window {
    id: loginWindow
    objectName: "loginWindow"
    
    // Window propertie
    width: 420 
    height: 560  
    visible: true
    title: qsTr("Login")

    // Flags to control window behavior
    flags: Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint


    // Custom properties
    property bool freezeWindow: false
    property bool criticalError: false
    property color popupText: "red"
    property int secondsRemaining: 30
    property var popupMain: null 

    // Function to change the image opacity
    property var changeImageOpacity: function(newOpacity) {
            image.opacity = newOpacity;
    }

    
    // Background image with drag functionality
    Image {
        id: image
        objectName: "image"
        width: 520
        source: "resources/images/camera.jpg"
        fillMode: Image.PreserveAspectFit
        opacity: 1.0

        // Mouse handling for dragging the window
        MouseArea {
            anchors.fill: parent
            property var lastMousePos
            drag.target: null 
            onPressed: {
                if (!freezeWindow) {
                    lastMousePos = Qt.point(mouseX, mouseY);
                }
            }
            onReleased: {
                lastMousePos = null; 
            }
            onPositionChanged: {
                if (lastMousePos && !freezeWindow) {
                    loginWindow.x += mouseX - lastMousePos.x;
                    loginWindow.y += mouseY - lastMousePos.y;
                }
            }
        }

    }

    // Loader for dynamically loading content
    Loader {
        id: myLoader
        objectName: "myLoader"
        anchors.fill: parent
        source:  Qt.resolvedUrl("app/ui/LoginWindow.qml")
        onLoaded: {
            console.log("LoginWindow content loaded.");
        }
        onStatusChanged: {
            console.log("Loader status changed:", status);
        }
    }

    Timer {
        id: popupTimer
        interval: 1000 
        repeat: true
        running: false
        onTriggered: {
            loginWindow.secondsRemaining -= 1;
            console.log("popupTimer.onTriggered");
            if (myLoader.status === Loader.Ready) {
                if (myLoader.source.toString() === "app/ui/LoadWindow.qml")
                console.log("true",loginWindow.secondsRemaining)
                {
                    var loadedComponent = myLoader.item;
                    loadedComponent.updateCountdown(loginWindow.secondsRemaining.toString());
                }
            }

            if (loginWindow.secondsRemaining <= 0) {

                loginWindow.secondsRemaining = 30;
            }
        }
    }
    
    // Handle window dimension changes
    Connections {
        target: loginWindow
        function onWidthChanged() {
            console.log("Window width changed to:", loginWindow.width);
            loginWindow.width = 420
        }
        function onHeightChanged() {
            console.log("Window height changed to:", loginWindow.height);
            loginWindow.height = 560; 
        }
    }

    // Listen for session view signals
    Connections {
        target: sessionview.error_manager
        function onShowError(error) {
            console.error("Error received from session view:", error);
            if (myLoader.source.toString() === "app/ui/LoadWindow.qml"){
                loginWindow.stopPopupTimer();
                myLoader.source = "app/ui/LoginWindow.qml"
            }
            showPopup(error);
        }
        function onShowCriticalError(error){
            console.error("Critical error received from session view:", error);
            loginWindow.criticalError = true
            showPopup(error);
        }
    }

    Connections {
        target: appstatus
        function onShowAppStateChanged() {
            var state = appstatus.get_state();
            console.log("onShowAppStateChanged:", state);
            if (state == "two_factory"){
                console.log("state two factore " )
                myLoader.source = "app/ui/Totp.qml"
            }else if( state == "in_request"){
                myLoader.source = "app/ui/LoadWindow.qml"
                popupTimer.start();
            }else if( state == "login_failed"){
                loginWindow.stopPopupTimer();
                myLoader.source = "app/ui/LoginWindow.qml"   
            }else if( state == "logged_in"){
                loginWindow.stopPopupTimer();
                loginWindow.openAppWindow()  
            }else if( state == "logged_out"){
                myLoader.source = "app/ui/LoginWindow.qml"   
            }
        }
    }

    // Function to display a popup with error messages
    function showPopup(errorMessage ) {
        if(loginWindow.popupMain){
            console.warn("Popup window is already open. Skipping new popup.");
            return;
        }

        console.log("Displaying popup with message:", errorMessage);

        // Adjust window state before showing the popup
        loginWindow.changeImageOpacity(0.5)
        loginWindow.freezeWindow = true
        myLoader.item.freezeComponents(true);

        // Load the popup dynamically
        var component = Qt.createComponent("app/ui/Popup.qml");
        if (component.status !== Component.Ready) {
            console.error("Failed to load Popup.qml:", component.errorString());
            return;
        }

        // Create the popup object
        var popupMain = component.createObject(loginWindow, {
            message: errorMessage,
            dynamicColor: loginWindow.popupText,
        });
        if (popupMain) {
            console.log("Popup instance created:", popupMain);
            popupMain.adjustSize();
            popupMain.show();
            loginWindow.popupMain = popupMain;
        }else {
            console.error("Failed to create popup instance.");
        }
    }

    function changeStaysOnTopHint(){
        console.log( " changeStaysOnTopHint " );
        flags &= ~Qt.WindowStaysOnTopHint;
    }

    function addWindowStaysOnTopHint() {
        loginWindow.flags = Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint;
    }

    function showWindow(){
        console.log("showWindow");
        visible = true;
        loginWindow.addWindowStaysOnTopHint();
        myLoader.source = "app/ui/LoginWindow.qml";
    }

    function openAppWindow() {
        console.log("loginWindow.openCompanyWindow");
        changeStaysOnTopHint();
        loginWindow.visible = false
        var component = Qt.createComponent("app/ui/App.qml");
        if (component.status === Component.Ready) {
            var appWindow = component.createObject(loginWindow, {"loginWindowRef": this});
            appWindow.show();
        } else {
            console.error("Cannot load App.qml", component.errorString());
        }
    }

    function stopPopupTimer() {
        console.log("loginWindow.stopPopupTimer")
        popupTimer.stop();
    }

    onClosing: {
        console.log("Window.onClosing processed");
        if(popupTimer.running){
            console.log("pupupTimer is running");
            loginWindow.stopPopupTimer();

        }
    }

}