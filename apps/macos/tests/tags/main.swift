import Foundation

var failures = 0
func check(_ ok: Bool, _ what: String) {
    print(ok ? "PASS" : "FAIL", what)
    if !ok { failures += 1 }
}

check(Tags.normalize([" Prod", "web", "PROD", "", "db "]) == ["prod", "web", "db"], "normalize: lower case, trimmed, no blanks or duplicates")
check(Tags.split("a, B ,,a") == ["a", "b"], "split: stored comma text")

let plain = TagQuery.parse("web 01")
check(plain.tags.isEmpty && plain.text == "web 01", "no tag: term keeps the text as typed")
let one = TagQuery.parse("tag:Prod")
check(one.tags == ["prod"] && one.text.isEmpty, "tag:Prod is the tag prod, no free text")
let both = TagQuery.parse("TAG:prod web TAG:db")
check(both.tags == ["prod", "db"] && both.text == "web", "several tag: terms combine; free text kept")
check(TagQuery.parse("tag:").tags.isEmpty, "bare tag: is free text")
check(both.admits(["db", "prod", "x"]), "admits: all tags present")
check(!both.admits(["prod"]), "admits: one missing refuses")
check(TagQuery.parse("web").admits([]), "admits: no tag terms admits all")

exit(failures == 0 ? 0 : 1)
