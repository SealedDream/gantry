import Foundation

// Fake accessibility elements: each getter answers whatever object the test gives it, as some
// real elements do (a number or an attributed string where a string is declared).
final class Element: NSObject {
    let role: AnyObject?, title: AnyObject?, value: AnyObject?
    var children: [AnyObject] = []
    init(role: AnyObject?, title: AnyObject? = nil, value: AnyObject? = nil, children: [AnyObject] = []) {
        self.role = role; self.title = title; self.value = value; self.children = children
    }
    @objc func accessibilityRole() -> AnyObject? { role }
    @objc func accessibilityTitle() -> AnyObject? { title }
    @objc func accessibilityValue() -> AnyObject? { value }
    @objc func accessibilityChildren() -> NSArray { children as NSArray }
}

var failures = 0
func check(_ ok: Bool, _ what: String) {
    print("\(ok ? "PASS" : "FAIL") \(what)")
    if !ok { failures += 1 }
}

// A role and title that are numbers (bridging them to String threw an Objective-C exception).
let odd = Element(role: NSNumber(value: 42), title: NSNumber(value: 7))
let rdp = Element(role: "AXPopUpButton" as NSString, value: "RDP" as NSString)
let result = Element(role: "AXMenuButton" as NSString, title: NSAttributedString(string: "Any result"))
let root = Element(role: "AXGroup" as NSString, children: [odd, Element(role: nil, children: [rdp, result]), NSObject()])

check(AXTree.text(odd, "accessibilityRole") == "42", "a number role reads as its description")
check(AXTree.text(NSObject(), "accessibilityTitle") == "", "an element without the attribute reads as empty")
check(AXTree.popUp(in: root, showing: "RDP") === rdp, "finds a pop-up by its value past elements with number attributes")
check(AXTree.popUp(in: root, showing: "Any result") === result, "finds a menu button by an attributed title")
check(AXTree.popUp(in: root, showing: "*") === rdp, "\"*\" finds the first pop-up")
check(AXTree.popUp(in: root, showing: "None") == nil, "no match gives nil")
check(AXTree.popUp(in: "not an element", showing: "*") == nil, "a non-object node gives nil")

// A cycle stops at the depth limit instead of recursing forever.
let loop = Element(role: "AXGroup" as NSString)
loop.children = [loop]
check(AXTree.popUp(in: loop, showing: "*") == nil, "a cycle in the tree ends at the depth limit")

exit(failures == 0 ? 0 : 1)
