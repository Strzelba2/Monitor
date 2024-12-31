import QtQuick 2.15
import QtQuick.Controls 2.15
import "../../resources/components"

Window {
    id: appWindow
    width: 800
    height: 800
    visible: true
    title: qsTr("app")

    flags: Qt.FramelessWindowHint

    property var loginWindowRef: null

    CustomButton {
        id: btnClose
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
                sessionview.logout()
                
            }
        }
    }

    Connections {
        target: sessionview
        function onLogoutSuccess() {
            console.info("onlogoutSuccess");
            appWindow.closeAndShowLogin()
        }
    }

    function closeAndShowLogin()
    {
        console.log("appWindow.closeAndShowLogin");
        
        if (loginWindowRef) {
            loginWindowRef.showWindow();
        }
        appWindow.destroy();
    }
}