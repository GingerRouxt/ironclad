import QtQuick
Canvas {
    id: icon
    property int symbol: 0
    property color ink
    implicitWidth: 20; implicitHeight: 20
    onInkChanged: requestPaint()
    onSymbolChanged: requestPaint()
    onPaint: {
        const c = getContext("2d")
        c.reset(); c.scale(width / 24, height / 24)
        c.strokeStyle = ink; c.lineWidth = 1.7; c.lineCap = "round"; c.lineJoin = "round"
        function path(points, close) { c.beginPath(); c.moveTo(points[0][0], points[0][1]); for (let i = 1; i < points.length; i++) c.lineTo(points[i][0], points[i][1]); if (close) c.closePath(); c.stroke() }
        if (symbol === 0) {
            for (let x of [4,14]) for (let y of [4,14]) c.strokeRect(x,y,6,6)
        } else if (symbol === 1) {
            path([[12,3],[20,6],[19,14],[16,18],[12,21],[8,18],[5,14],[4,6]],true)
            path([[8,12],[11,15],[16,9]],false)
        } else if (symbol === 2) {
            c.strokeRect(4,4,16,16);path([[4,9],[20,9]],false);path([[9,9],[9,20]],false)
        } else if (symbol === 3) {
            path([[12,3],[15,9],[21,12],[15,15],[12,21],[9,15],[3,12],[9,9]],true)
        } else if (symbol === 4) {
            path([[3,12],[7,12],[10,5],[14,19],[17,12],[21,12]],false)
        } else {
            c.beginPath();c.arc(12,12,9,0,Math.PI*2);c.stroke();path([[12,7],[12,12],[16,14]],false)
        }
    }
}
