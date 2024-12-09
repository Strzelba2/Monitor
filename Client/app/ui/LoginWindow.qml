import QtQuick 2.15
import QtQuick.Controls 2.15

import "../../resources/components"

Item {
    id:loginLoader

    CustomButton {
        id: btnClose
        objectName: "btnClose"
        width: 30
        height: 30
        opacity: 1
        visible: true
        text: "X"
        anchors.left: parent.left
        anchors.top: parent.top
        anchors.leftMargin: 365
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
                console.log("Close button clicked. Closing the login window.");
                if (loginWindow.popupMain) {
                    console.log("Destroying popupMain instance.");
                    loginWindow.popupMain.destroy();
                    loginWindow.popupMain = null;
                }
                loginWindow.close();
            }
        }
    }

    CustomTextField {
        id: textUsername
        objectName: "textUsername"
        x: 50
        y: 185
        opacity: 1
        anchors.bottom: textPassword.top
        anchors.bottomMargin: 20
        anchors.left: loginWindow.left
        anchors.leftMargin: 50
        placeholderText: "Username"
        text: sessionview ? sessionview.textUsername : ""
        onAccepted:
        {
            console.log("Username field: Enter key pressed.");
        }
    }

    CustomTextField {
        id: textPassword
        objectName: "textPassword"
        x: 50
        y: 195
        opacity: 1
        anchors.bottom: btnLogin.top
        anchors.bottomMargin: 145
        anchors.left: loginWindow.left
        anchors.leftMargin: 90
        placeholderText: "Password"
        echoMode: TextInput.Password
        onAccepted:
        {
             console.log("Password field: Enter key pressed.");
        }
    }

    Switch {
        id: rememberMe
        objectName: "rememberMe"
        checked: sessionview ? sessionview.switch_state : false

        Text {
            width: 151
            height: 36
            text: qsTr("Remember me")
            font.family: "Helvetica"
            font.pointSize: 10
            color: "grey"
            anchors.left: parent.left
            verticalAlignment: Text.AlignVCenter
            anchors.leftMargin: 65
        }

        indicator: Rectangle{
            id: rememberMeInd
            objectName: "rememberMeInd"
            implicitWidth: 40
            implicitHeight: 20
            x: rememberMe.width - width - rememberMe.rightPadding
            y: parent.height / 2 - height / 2
            radius: 10
            color:  rememberMe.hovered ? "#c6c8cc" : "#d6d8dc"
            border.color: "grey"

            Rectangle {
               x: rememberMe.checked ? parent.width - width : 0
               width: 20
               height: 20
               radius: 10
               border.color: "grey"
           }

        }

        anchors.left: parent.left
        anchors.leftMargin: 50
        anchors.bottom: textPassword.bottom
        font.styleName: "Normalny"
        font.pointSize: 10
        anchors.bottomMargin: -125
        onToggled: {
            console.log("Remember me switch toggled:", checked ? "ON" : "OFF");
            if(checked) {
                console.log("switch on");
                sessionview.handle_switch_toggled(true,textUsername.text.trim())
            } else {
                console.log("switch off");
                sessionview.handle_switch_toggled(false)

            }
        }

        Component.onCompleted: {
            console.log("Switch component initialized. Current state:", rememberMe.checked);
        }
    }

    Text {
        y: 340
        width: 150
        height: 35
        text: qsTr("Forgotten password?")
        font.family: "Helvetica"
        font.pointSize: 10
        color: "#cf953e"
        anchors.left: rememberMe.left
        verticalAlignment: Text.AlignVCenter
        anchors.leftMargin: 183

        MouseArea {
            anchors.fill: parent
             onClicked: console.log("Forgotten password clicked.");
        }
    }

    CustomButton {
        id: btnLogin
        objectName: "btnLogin"
        width: 320
        height: 50
        opacity: 1
        text: "LOGIN"
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.leftMargin: 50
        anchors.topMargin: 390
        font.pointSize: 16
        font.family: "arial"
        colorPressed: "#d9d7d4"
        colorMouseOver: "#bfbdbb"
        colorDefault: "#b3b2b1"

        MouseArea {
            id: mauselogin
            anchors.fill: parent
            onClicked:{
                console.log("Login button clicked.");
            }
        }
    }

    function freezeComponents(freeze)  {
        console.log("Freezing components:", freeze);
        textPassword.enabled = !freeze;
        btnLogin.enabled = !freeze;
        textUsername.enabled = !freeze;
        rememberMe.enabled =  !freeze;
    }

    function get_rememberMe (){
        console.log("Getting 'Remember me' state:", rememberMe.checked);
        return rememberMe.checked;
    }

}