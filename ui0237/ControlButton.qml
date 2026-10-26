import QtQuick
import QtQuick.Controls
import "Design.js" as Design
Button {
    id: control
    property color ink
    property color muted
    property color accent
    property color accentInk
    property color surface
    property color rail
    property color line
    property bool primary: false
    property bool quiet: false
    implicitHeight: Design.controlHeight
    implicitWidth: Math.max(42, caption.implicitWidth + 28)
    leftPadding: 14; rightPadding: 14; topPadding: 8; bottomPadding: 8
    hoverEnabled: true
    focusPolicy: Qt.StrongFocus
    background: Rectangle {
        radius: 8
        color: control.primary ? control.accent : control.hovered ? control.surface : control.quiet ? "transparent" : control.rail
        border.width: control.activeFocus ? 2 : 1
        border.color: control.activeFocus ? control.accent : control.primary ? control.accent : control.quiet ? "transparent" : control.line
        opacity: control.enabled ? 1 : 0.5
    }
    contentItem: BodyText {
        id: caption
        text: control.text
        color: control.primary ? control.accentInk : control.ink
        font.weight: Font.Medium
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
        opacity: control.enabled ? 1 : 0.55
    }
}
