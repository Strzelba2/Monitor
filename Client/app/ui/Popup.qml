import QtQuick 2.15
import QtQuick.Controls 2.15
import "../../resources/components"

Window {
    id: popupMain
    objectName: "popupMain"
    width: 400
    height: 200
    visible: true
    title: qsTr("ErrorPopup")

    flags: Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint

    property string message: "default"
    property color dynamicColor: "red"
    property color backgraundColor: "#DFDCDC"
    property bool animationClose: false

    color: "transparent"

    Rectangle {
        id: roundedContainer
        width: parent.width
        height: parent.height
        radius: 10
        color: "#747a76"
        scale: 0.5 
        border.color: "black"
        border.width: 1

        SequentialAnimation on visible {
            PropertyAnimation { target: roundedContainer; property: "scale"; from: 0.5; to: 1.0; duration: 300 }
        }

        SequentialAnimation on visible {
            running: animationClose
            PropertyAnimation { target: roundedContainer; property: "scale"; from: 1.0; to: 0.5; duration: 300 }
            ScriptAction { script: popupMain.visible = false }
        }

        Rectangle {

            property int customWidthMargin: 30;
            property int customHeightMargin: 20;
            id: popupRec
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.top: parent.top
            anchors.topMargin: (popupMain.width - width)/2
            width: popupMain.width - customWidthMargin
            height: popupMain.height - popupButton.height - customHeightMargin*2
            color: backgraundColor
            border.color: "black"
            radius: 10

            TextArea {
                id: popupText
                text: popupMain.message
                anchors.fill: parent
                anchors.margins: 5
                wrapMode: TextArea.Wrap
                horizontalAlignment: Text.AlignHCenter
                verticalAlignment: Text.AlignVCenter
                readOnly: true
                color: dynamicColor
                background: Rectangle {
                    color: backgraundColor
                }
                font.pixelSize: 16
            }
        }

        Rectangle {
            id: moveMouse
            color: "#00000033"
            anchors.fill: parent
            MouseArea {
                anchors.fill: parent
                property point lastMousePos: Qt.point(0, 0)
                onPressed: { lastMousePos = Qt.point(mouseX, mouseY); }
                onMouseXChanged: popupMain.x += (mouseX - lastMousePos.x)
                onMouseYChanged: popupMain.y += (mouseY - lastMousePos.y)
            }
        }

        CustomButton {
            id: popupButton
            objectName: "popupButton"
            text: "OK"
            anchors.bottom: parent.bottom
            anchors.bottomMargin: 10
            anchors.horizontalCenter: parent.horizontalCenter
            width: parent.width * 0.5
            height: parent.height * 0.15
            font.pointSize: 14
            font.family: "arial"
            colorPressed: "#d9d7d4"
            colorMouseOver: "#bfbdbb"
            colorDefault: "#b3b2b1"
            onClicked: popupMain.buttonClickedFunction()
        }
        onWidthChanged: adjustSize()
        onHeightChanged: adjustSize() 
    }

    function adjustSize() {
        console.log("Adjusting popup size...");
        var maxWidth = 600;
        var maxHeight = 400;
        var minHeightConst = 200;
        var currentFontSize = popupText.font.pixelSize;
        var minWidth = Math.min(popupText.contentWidth + 30, maxWidth) + popupRec.customWidthMargin + popupText.anchors.margins;

        if (popupMain.width < minWidth){
            popupMain.width = maxWidth;
        }

        var minHeight = Math.min(popupText.contentHeight, maxHeight)+popupButton.height + popupRec.customHeightMargin*2 + popupRec.anchors.topMargin;

        if((minHeight < minHeightConst) && ((minHeight-minHeightConst)>2) ){
            popupMain.height = minHeightConst;
        }

        if((minHeight < popupMain.height )&&(minHeight > minHeightConst)&&((popupMain.height-minHeight)>2)){
            popupMain.height = minHeight;
        }
        if(( popupMain.height < minHeight)&&(minHeight > minHeightConst)&&((minHeight-popupMain.height>2))){
            popupMain.height = minHeight;
        }
        if (( popupText.contentHeight > maxHeight)) {
            popupText.font.pixelSize = currentFontSize - 1;
        }
    }
    property var buttonClickedFunction: function() {
        console.log("buttonClickedFunction executed: Closing popup.");
        popupMain.animationClose = true;
        closeTimer.start();   
    }

    Timer {
        id: closeTimer
        interval: 300; 
        repeat: false;
        running: false;
        onTriggered: {
            console.log("closeTimer triggered: Finalizing popup closure.");

            if (loginWindow.criticalError) {
                console.info("Critical error detected. Closing login window.",loginWindow.criticalError);
                if (loginWindow.appMain){
                    loginWindow.showWindow()
                }
                loginWindow.close();
                return;
            }
   
            if(loginWindow.appMain){
                loginWindow.appMain.freezeComponents(false)
                loginWindow.popupMain = null;
                loginWindow.appMain.addWindowStaysOnTopHint()
                loginWindow.freezeWindow = false;
            }else{
                myLoader.item.freezeComponents(false); 
                sessionview.refresh_state();
                loginWindow.freezeWindow = false;
                loginWindow.changeImageOpacity(1);
                loginWindow.popupMain = null;     
            }

            console.log("Destroying popupMain instance.");
            popupMain.destroy();
        }
    }
}