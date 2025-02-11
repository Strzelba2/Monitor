import QtQuick 6.7
import QtQuick.Controls 6.7
import "../../resources/components"

Item {

    Image {
        id: streamImage
        anchors.fill: parent
        width: parent.width
        height: parent.height - 50
        fillMode: Image.PreserveAspectFit
        source: "image://stream/img"
        cache: false
    }

    Connections{
        target: sessionview.stream_display

        function onImageChanged(image) {
   
            var timestamp = new Date().getTime();
            streamImage.source = "image://stream/img?t=" + timestamp;
         
        }   
    }
}