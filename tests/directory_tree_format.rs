use eedfs::format::{
    directory::{Directory, Entry},
    directory_tree::{Child, FANOUT, MAX_ENTRIES, MAX_HEIGHT, Page, PageRef, Root},
    inode,
};

fn entry(name: &str) -> Entry {
    Entry {
        name: name.into(),
        id: [4; 16],
        kind: inode::FILE,
    }
}
fn child(first: &str) -> Child {
    Child {
        first: first.into(),
        page: PageRef {
            id: [5; 16],
            len: 128,
        },
    }
}

#[test]
fn directory_roots_and_pages_roundtrip_and_old_inline_reader_rejects_tree() {
    for page in [
        Page::Leaf(vec![entry("a"), entry("b")]),
        Page::Branch(vec![child("a"), child("b")]),
    ] {
        let bytes = page.encode().unwrap();
        assert_eq!(&bytes[..10], b"EEDFSDPG\x01\x00");
        assert_eq!(Page::decode(&bytes).unwrap(), page);
        for end in 0..bytes.len() {
            assert!(Page::decode(&bytes[..end]).is_err());
        }
        let mut extra = bytes;
        extra.push(0);
        assert!(Page::decode(&extra).is_err());
    }
    let root = Root {
        child: child("a"),
        height: 1,
        entries: 100,
    };
    let bytes = root.encode().unwrap();
    assert!(Root::is_tree(&bytes));
    assert_eq!(Root::decode(&bytes).unwrap(), root);
    assert!(Directory::decode(&bytes).is_err());
    for end in 0..bytes.len() {
        assert!(Root::decode(&bytes[..end]).is_err());
    }
}

#[test]
fn directory_pages_reject_invalid_names_order_bounds_and_empty_nodes() {
    for entries in [
        vec![],
        vec![entry("b"), entry("a")],
        vec![entry("a"), entry("a")],
        vec![entry("../bad")],
        vec![entry("a"); FANOUT + 1],
    ] {
        assert!(Page::Leaf(entries).encode().is_err());
    }
    for children in [
        vec![],
        vec![child("b"), child("a")],
        vec![child("a"); FANOUT + 1],
    ] {
        assert!(Page::Branch(children).encode().is_err());
    }
    let mut root = Root {
        child: child("a"),
        height: 0,
        entries: 1,
    };
    root.height = MAX_HEIGHT + 1;
    assert!(root.encode().is_err());
    root.height = 0;
    root.entries = MAX_ENTRIES + 1;
    assert!(root.encode().is_err());
    root.entries = 0;
    assert!(root.encode().is_err());
    root.entries = 1;
    root.child.page.len = 0;
    assert!(root.encode().is_err());
}
