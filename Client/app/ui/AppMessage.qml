import QtQuick 6.7
import QtQuick.Controls 6.7

Item {
    property string dynamicHeader: "Welcome to Server Service." 
    property string dynamicMessage: "Please click 'Servers' to subcribe session for a Server."

    Rectangle {
        id: topBar
        height: 50
        width: parent.width
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.topMargin: 70
        color: "transparent"

        Text {
            id: messageHeader
            anchors.centerIn: parent
            text: dynamicHeader
            font.pixelSize: 40
            font.family: "arial"
            color: "#9e6c38"
        }
    
    }

    Text {
        id: appDynamicMessage
        anchors.centerIn: parent
        text: dynamicMessage
        font.pixelSize: 20
        font.family: "arial"
        color: "#9e6c38"
    }
}