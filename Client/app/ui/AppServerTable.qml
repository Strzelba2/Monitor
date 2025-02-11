import QtQuick 6.7
import QtQuick.Controls 6.7
import "../../resources/components"

Item {
    Rectangle {
        id:bookItem
        anchors.fill: parent
        anchors.margins: 5
        radius: 5
        color: "transparent"

        HorizontalHeaderView {
            id: horizontalHeader
            anchors.left: tableView.left
            anchors.bottom: tableView.top
            syncView: tableView
            height: 50
            clip: true

            delegate: Rectangle {
                id: headerDelegate
                width: tableView.columnWidthProvider() 
                height: parent.height
                color: "lightgray"
                border.width: 1
                radius: 5
                border.color: "black"

                Text {
                    anchors.centerIn: parent
                    anchors.verticalCenter: parent.verticalCenter
                    text: tableView.model.headerData(index, Qt.Horizontal)
                    font.pointSize: 12
                    font.family: "Arial"
                }
            }
        }

        VerticalHeaderView {
            id: verticalHeader
            anchors.top: tableView.top
            anchors.right: tableView.left
            width: 30
            syncView: tableView
            clip: true

            delegate: ItemDelegate {

                width: verticalHeader.width

                Text {
                    anchors.centerIn: parent
                    text: tableView.model.headerData(index, Qt.Vertical)
                    font.pointSize: 12
                    font.family: "Arial"
                }

                background: Rectangle {
                    id: headerBack
                    color: "lightgray"
                    height: parent.height
                    width: verticalHeader.width
                    border.width: 1
                    radius: 5
                    border.color: "black"
                }
            }

        }

        TableView {
            id: tableView
            anchors.leftMargin: verticalHeader.width
            anchors.topMargin: horizontalHeader.height + 10
            anchors.fill: parent
            columnSpacing: 1
            rowSpacing: 1
            clip: true
            resizableColumns : false
            model: sessionview.servers

            columnWidthProvider: function() {
                console.log("columnWidthProvide:" );
                return (bookItem.width - verticalHeader.width - 5) / 4; 
            }

            delegate: Rectangle {
                implicitWidth: 100
                implicitHeight: 50
                border.width: 1
                radius: 5
                color : "gray"
                border.color: "black"

                Text {
                    id: textItem
                    anchors.centerIn: parent
                    text: model.display
                    font.pointSize: 12
                    font.family: "arial"
                    visible: model.display !== "Subscribe" 
                }

                CustomButton {
                    id: appBtnSubscribe
                    width: parent.width
                    height: parent.height
                    anchors.centerIn: parent
                    text: model.display
                    visible: model.display === "Subscribe" 
                    font.pointSize: 16
                    font.family: "arial"
                    colorPressed: "#d9d7d4"
                    colorMouseOver: "#bfbdbb"
                    colorDefault: "#d57818"
                    radiusBorder: 5
                    onClicked: {
                        console.log("Clicked Subscribe for:", model.name)
                        sessionview.generate_session(model.name)

                    }
                }
            }
        }
    }
}
