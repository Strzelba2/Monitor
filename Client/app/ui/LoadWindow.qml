import QtQuick 2.15
import QtQuick.Controls 2.15
import "../../resources/components"

Item {
    signal updateCountdown(string text)
    property bool showLoadWindow: true

    CustomButton {
        id: btnClose
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
                loginWindow.close();
            }
        }
    }
    Canvas {
        id: canvas
        width: 300
        height: 300
        anchors.centerIn: parent

        property real startAngle: 0
        property real endAngle: 40

        onPaint: {
            var ctx = getContext("2d");
            var centerX = width / 2;
            var centerY = height / 2;
            var radius = Math.min(width, height) / 3;
            ctx.clearRect(0, 0, width, height);
            ctx.beginPath();
            ctx.arc(centerX, centerY, radius, 0, 2 * Math.PI, false);
            ctx.lineWidth = 20;
            ctx.strokeStyle = "#DFDCDC";
            ctx.stroke();
            ctx.beginPath();
            ctx.arc(centerX, centerY, radius, startAngle * Math.PI / 180, endAngle * Math.PI / 180, false);
            ctx.strokeStyle = "#b3b2b1";
            ctx.stroke();
        }

        Timer {
            id: progresTimer
            interval: 20
            running: true
            repeat: true
            onTriggered: {
                canvas.startAngle += 5;
                canvas.endAngle += 5;
                if (canvas.startAngle >= 360) canvas.startAngle = 0;
                if (canvas.endAngle >= 360) canvas.endAngle = 0;
                canvas.requestPaint();
            }
        }
    }

    Text {
        id: countdownText
        font.pixelSize: 40
        font.family: "arial"
        anchors.centerIn: parent
        text: "30"
        color: "#b3b2b1"
    }

    function freezeComponents(freeze)  {
        console.log("onFreezeComponents!" + !freeze);
        progresTimer.stop();
        loginWindow.stopPopupTimer();
    }

    function handleUpdateCountdown(newText) {
        countdownText.text = newText;
    }

    function restartProgressTimer() {
            progresTimer.restart();
    }

    Component.onCompleted: {
        updateCountdown.connect(handleUpdateCountdown);
    }

}
