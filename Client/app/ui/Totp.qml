import QtQuick 2.15
import QtQuick.Controls 2.15
import "../../resources/components"

Item {
    property bool showTotp: true

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
                loginWindow.close()
            }
        }
    }

    CustomTextField {
        id: totpcode
        objectName: "totpcode"
        x: 50
        y: 185
        opacity: 1
        anchors.bottom: totpVerify.top
        anchors.bottomMargin: 100
        anchors.left: loginWindow.left
        anchors.leftMargin: 50
        placeholderText: "Code"
        enabled: true
    }

    CustomButton {
        id: totpVerify
        objectName: "totpVerify"
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
        enabled: true

        MouseArea {
            id: mauselogin
            anchors.fill: parent
            onClicked: sessionview.totp_login(totpcode.text)
        }
    }

    function freezeComponents(freeze)  {
        console.log("onFreezeComponents!" + !freeze)
        totpcode.enabled = !freeze;
        totpVerify.enabled = !freeze;
    }

}
