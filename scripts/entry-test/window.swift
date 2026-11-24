import CoreGraphics
import Foundation

let pid = Int(CommandLine.arguments[1])
let windows = CGWindowListCopyWindowInfo([.optionOnScreenOnly], kCGNullWindowID) as? [[String: Any]] ?? []
for window in windows where window[kCGWindowOwnerPID as String] as? Int == pid &&
    window[kCGWindowLayer as String] as? Int == 0 {
    if let bounds = window[kCGWindowBounds as String] as? [String: Any],
       let height = bounds["Height"] as? Double, height > 300,
       let id = window[kCGWindowNumber as String] as? Int {
        print(id)
        exit(0)
    }
}
exit(1)
