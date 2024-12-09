import QtQuick 2.15
import QtQuick.Controls 2.15

TextField {
    id: textField

    property color colorDefault: "#edeaf2"
    property color colorOnFocus: "#c6c8cc"
    property color colorMouseOver: "#d6d8dc"

    QtObject{
        id: internal
        property var dynamicColor: if(textField.focus){
                                        textField.focus ? colorOnFocus : colorDefault;
                                   }else{
                                       textField.hovered ? colorMouseOver : colorDefault;
                                   }
    }

    implicitWidth: 320
    implicitHeight: 50
    verticalAlignment: Text.AlignVCenter
    font.pointSize: 11
    font.family: "Arial"
    leftPadding: 7
    topPadding: 6
    horizontalAlignment: Text.AlignHCenter
    placeholderText: qsTr("Type something")
    color: "grey"
    text: ""
    background: Rectangle {
        color: internal.dynamicColor
        radius: 10
        border.color: "#bfbdbb"
        border.width: 2
    }
    selectByMouse: true
    selectedTextColor: "grey"
    selectionColor: "grey"
    placeholderTextColor: "grey"

    onTextChanged: {
        console.log("CustomTextFiel.onTextChanged")
        calculateFontSize()
    }

    function calculateFontSize() {
        const maxTextWidth = textField.implicitWidth - 10;
        while (textField.contentWidth > maxTextWidth && textField.font.pixelSize > 9) {
            textField.font.pixelSize -= 1;
        }
    }

    Component.onCompleted:{
        console.log("CustomTextFiel.onCompleted")
        calculateFontSize()
    }
}

