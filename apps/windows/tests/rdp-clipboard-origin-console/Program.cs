// SEC-6 checks: text one RDP session's server put on the Windows clipboard is offered only back to that session's
// own echo rule, never to another session, until the clipboard changes again.
using Bastion.Shell;

var failures = 0;
void Check(bool ok, string name) { Console.WriteLine((ok ? "PASS " : "FAIL ") + name); if (!ok) failures++; }
object a = new(), b = new();

RdpClipboardOrigin.ResetForTests();
Check(RdpClipboardOrigin.MayOffer(b, 1), "local copy with no server write is offered");

RdpClipboardOrigin.MarkRemoteWrite(a, 10);
Check(!RdpClipboardOrigin.MayOffer(b, 10), "server A's text is not offered to session B");
Check(RdpClipboardOrigin.MayOffer(a, 10), "session A keeps its own echo rule");
Check(RdpClipboardOrigin.MayOffer(b, 11), "a later local copy is offered to session B");

RdpClipboardOrigin.MarkRemoteWrite(b, 12);
Check(!RdpClipboardOrigin.MayOffer(a, 12), "server B's text is not offered to session A");

RdpClipboardOrigin.MarkRemoteWrite(a, 20);
RdpClipboardOrigin.Forget(a);
Check(!RdpClipboardOrigin.MayOffer(b, 20), "after A closes, its text is still not offered to B");
Check(RdpClipboardOrigin.MayOffer(b, 21), "after A closes, the next local copy is offered to B");

Console.WriteLine(failures == 0 ? "ALL PASS" : $"{failures} FAILED");
return failures == 0 ? 0 : 1;
