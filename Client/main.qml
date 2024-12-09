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
        target: sessionview
        function onShowError(error) {
            console.error("Error received from session view:", error);
            showPopup(error);
        }
        function onShowCriticalError(error){
            console.error("Critical error received from session view:", error);
            loginWindow.criticalError = true
            showPopup(error);
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
}