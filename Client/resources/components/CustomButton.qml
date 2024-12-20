import QtQuick 2.15
import QtQuick.Controls 2.15

Button {
    id: button
    flat:true

    property color colorDefault: "#4891d9"
    property color colorMouseOver: "#55AAFF"
    property color colorPressed: "#3F7EBD"
    property bool borderButton: false

    QtObject{
        id: internal
        property var dynamicColor: if(button.down){
                                       button.down ? colorPressed : colorDefault;
                                   }else{
                                       button.hovered ? colorMouseOver : colorDefault;
                                   }
    }

    text: qsTr("Button")
    contentItem: Item{
        Text {
            id: name
            text: button.text
            font: button.font
            color: borderButton ? "grey" : "#ffffff"
            anchors.verticalCenter: parent.verticalCenter
            anchors.horizontalCenter: parent.horizontalCenter
        }
    }

    background: Rectangle{
        color: internal.dynamicColor
        radius: 10
        border.color: "#bfbdbb"
        border.width: borderButton ? 2 : 0
    }
}



