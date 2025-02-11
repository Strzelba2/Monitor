import QtQuick 6.7
import QtQuick.Controls 6.7
import "../../resources/components"

Window {
    id: appWindow
    objectName: "appWindow"
    width: 800
    height: 800
    visible: true
    title: qsTr("app")

    flags: Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint

    ListModel {
        id: buttonModel
        ListElement { text: "Servers"; enabled: true; action: function() { showServers() } }
        ListElement { text: "View"; enabled: true; action: function() { view(loaderRec.width, loaderRec.height) } }
        ListElement { text: "Logout"; enabled: true; action: function() { logout() } }
    }

    Image {
        id: image
        objectName: "image"
        width: parent.width
        source: "../../resources/images/camera.jpg"
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
                    appWindow.x += mouseX - lastMousePos.x;
                    appWindow.y += mouseY - lastMousePos.y;
                }
            }
        }

    }

    CustomButton {
        id: appBtnClose
        objectName: "appBtnClose"
        width: 30
        height: 30
        opacity: 1
        visible: true
        text: "X"
        anchors.right:  parent.right
        anchors.top: parent.top
        anchors.rightMargin: 30
        clip: false
        anchors.topMargin: 22
        colorPressed: "#d9d7d4"
        font.family: "Segoe UI"
        colorMouseOver: "#bfbdbb"
        colorDefault: "#b3b2b1"
        font.pointSize: 16

        MouseArea {
            id: myMouseId
            anchors.fill: parent
            onClicked:{
                if (loginWindow.popupMain) {
                    console.log("Destroying popupMain instance.");
                    loginWindow.popupMain.destroy();
                    loginWindow.popupMain = null;
                }
                loginWindow.appMain = null
                loginWindow.changeImageOpacity(1);
                sessionview.logout()
                
            }
        }
    }

    Rectangle {
        id: roundedRectangle
        anchors.topMargin: 80
        anchors.bottomMargin: 80
        anchors.leftMargin: 40
        anchors.rightMargin: 40
        anchors.fill: parent
        radius: 20 
        color: "transparent"
        border.color: "#b3b2b1" 
        border.width: 2

        Rectangle {
            id: topBar
            height: 50
            width: parent.width
            anchors.top: parent.top
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.topMargin: 20
            color: "transparent"

            Row {
                spacing: 20
                // anchors.horizontalCenter: parent.horizontalCenter
                anchors.centerIn: parent 
                anchors.verticalCenter: parent.verticalCenter
                anchors.margins: 10

                Repeater {
                    model: buttonModel
                    delegate: CustomButton {
                        text: model.text
                        width: 150
                        height: 50
                        enabled: model.enabled
                        font.pointSize: 16
                        font.family: "arial"
                        colorPressed: "#d9d7d4"
                        colorMouseOver: "#bfbdbb"
                        colorDefault: "#b3b2b1"

                        MouseArea {
                            anchors.fill: parent
                            onClicked: {
                                if (typeof model.action === "function") {
                                    model.action(); // Explicitly call the function
                                } else {
                                    console.error("Action is not a function for");
                                }
                            }
                        }

                    }
                }
            }
        }

        Rectangle {
            id: loaderRec
            anchors.topMargin: 100
            anchors.bottomMargin: 40
            anchors.leftMargin: 40
            anchors.rightMargin: 40
            anchors.fill: parent
            radius: 15 
            color: "transparent"
            border.color: "#b3b2b1" 
            border.width: 1

            Loader {
                id: appLoader
                objectName: "appLoader"
                anchors.fill: parent
                source:  Qt.resolvedUrl("AppMessage.qml")
                onLoaded: {
                    console.log("appLoader content loaded.", item);
                }
                onStatusChanged: {
                    console.log("Loader status changed:", status);
                }
            }
        }
    }

    Connections {
        target: appWindow
        function onWidthChanged() {
            appWindow.width = 800
        }
        function onHeightChanged() {
            appWindow.height = 800; 
        }
    }

    Connections {
        target: sessionview
        function onLogoutSuccess() {
            console.info("onlogoutSuccess");
            appWindow.closeAndShowLogin()
        }
    }

    Component.onCompleted: {
        console.log("appBtnClose.x:", appBtnClose.x, "appBtnClose.y:", appBtnClose.y);
    }

    Connections {
        target: appstatus
        function onShowAppSessionStateChanged() {
            var state = appstatus.get_session_state();
            console.log("onShowAppSessionStateChanged:", state);
            if (state === "show_servers"){
                console.log("state show_servers" )
                appLoader.source = "AppServerTable.qml"
            }else if(state === "session_available"){
                console.log("state session_available" )
                appLoader.source = "AppMessage.qml"
                 Qt.callLater(() => {
                    if (appLoader.item) {
                        appLoader.item.dynamicHeader = "Session Available!";
                        appLoader.item.dynamicMessage = "Please Click View to connect with Server";
                    }
                });
            }else if(state === "session_unavailable"){
                console.log("state session_unavailable" )
                if (appLoader.source.toString() === "AppMessage.qml"){
                    console.log("appMessage is exposed")
                    appLoader.source = ""
                }
                appLoader.source = "AppMessage.qml" 
            }else if (state === "connected"){
                console.log("state connected" )
                appLoader.source = "AppStream.qml" 
            }
        }
    }

    function showServers(){
        console.log("appWindow.showServers");
        var state = appstatus.get_session_state();
        if (state === "session_unavailable"){
            sessionview.get_servers_available("");
        }else if (state === "show_servers"){
             sessionview.get_servers_available("");
        }else if (state === "in_progres") {
            loginWindow.showPopup("Process in the middle of a request, Please wait for completion  ")
        }else if (state === "session_available"){
            loginWindow.showPopup("User currently has an active session. Please press view to connect to the server or logout to log out of the session")
        }else if (state === "connected"){
            loginWindow.showPopup("Please press logout to subscribe a new session")
        }

    }

    function view(width, height){
        console.log("appWindow.view");
        var state = appstatus.get_session_state();
        if (state === "session_available"){
            sessionview.connect_with_server(width, height);
        }else if (state === "show_servers"){
            loginWindow.showPopup("Please press subcribe to request session")
        }else if (state === "in_progres") {
            loginWindow.showPopup("Process in the middle of a request, Please wait for completion  ")
        }else if (state === "connected"){
            loginWindow.showPopup("Please press logout to subscribe a new session")
        }else if (state === "session_unavailable"){
            loginWindow.showPopup("Please press Servers to chose server for connection")
        }
    }

    function logout(){
        console.log("appWindow.logout");
        var state = appstatus.get_session_state();
        if (state === "connected"){
            sessionview.server_logout();
        }else if (state === "show_servers"){
            loginWindow.showPopup("Please press subcribe to request session")
        }else if (state === "in_progres") {
            loginWindow.showPopup("Process in the middle of a request, Please wait for completion  ")
        }else if (state === "session_available"){
            sessionview.server_logout();
        }else if (state === "session_unavailable"){
            loginWindow.showPopup("Please press Servers to chose server for connection")
        }
    }

    function closeAndShowLogin(){
        console.log("appWindow.closeAndShowLogin");
        
        if (loginWindow) {
            loginWindow.showWindow();
        }
        appWindow.destroy();
    }

    function freezeComponents(freeze)  {
        console.log("Freezing components:", freeze);
        for (var i = 0; i < buttonModel.count; i++) {
            buttonModel.get(i).enabled = !freeze;
        }
    } 

    function changeStaysOnTopHint(){
        console.log( " changeStaysOnTopHint " );
        flags &= ~Qt.WindowStaysOnTopHint;
    }

    function addWindowStaysOnTopHint() {
        flags = Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint;
    }
}