# idapython scripts

\[underway...\]

A collection of IDApython scripts sorted by topic:

## Heap Exploitation
* **Find Element Object** - This script will list all objects, sizes,  heap (default/isolated) that xref HeapAlloc.

*Sample output*:
```
Address      | Element object                                                                        | Size                     | Heap                     
-------      | --------------                                                                        | ----                     | ----                     
0x74c3762eL  | CView::RenderElement(CElement *,CDispDrawContext *,HDC__ *,IUnknown *,tagRECT *,tagRE | 0x50 bytes               | _g_hProcessHeap          
0x74c383aeL  | CAreaElement::CreateElement(CHtmTag *,CDoc *,CElement * *)                            | 0x64 bytes               | _g_hProcessHeap          
0x74c4d145L  | CInsertSpliceUndo::CreateUnit(void)                                                   | 0x28 bytes               | _g_hProcessHeap          
0x74c4fb3cL  | CStyleSheet::addRuleIE8StandardsMode(ushort *,ushort *,long,long *)                   | 0x1C bytes               | _g_hProcessHeap          
```
