use cocryptfs::format::{file_index::*, header::NamingConfig};
fn child() -> Child {
    Child {
        first: 0,
        end: 10,
        count: 1,
        id: [1; 16],
        len: 32,
    }
}
#[test]
fn file_index_pages_validate_bounds_order_types_and_canonical_frames() {
    let page = Page::Leaf(vec![Record {
        start: 0,
        end: 10,
        value: Value::Extent {
            allocation: [2; 16],
            index: 0,
        },
    }]);
    let bytes = page.encode().unwrap();
    assert_eq!(Page::decode(&bytes).unwrap(), page);
    for i in 0..bytes.len() {
        assert!(Page::decode(&bytes[..i]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Page::decode(&trailing).is_err());
    assert!(Page::Leaf(vec![]).encode().is_err());
    assert!(
        Page::Leaf(vec![Record {
            start: 3,
            end: 2,
            value: Value::Version(1)
        }])
        .encode()
        .is_err()
    );
    assert!(
        Page::Leaf(vec![Record {
            start: 0,
            end: 10,
            value: Value::Version(0)
        }])
        .encode()
        .is_err()
    );
    assert!(Page::Branch(vec![child(), child()]).encode().is_err());
    let mut root = Root {
        child: child(),
        height: 0,
    };
    root.validate().unwrap();
    root.height = MAX_HEIGHT + 1;
    assert!(root.validate().is_err());
    root.height = 0;
    root.child.count = MAX_ENTRIES + 1;
    assert!(root.validate().is_err());
}
#[test]
fn file_index_summaries_reject_impossible_layouts_and_old_inode_v6() {
    let mut root = FileRoot {
        size: 0,
        allocated: 0,
        naming: NamingConfig {
            algorithm: cocryptfs::crypto::naming::algorithm().unwrap(),
            key: [3; 32],
        },
        extents: None,
        versions: None,
        flags: [0; 6],
        inline: vec![],
    };
    root.validate(1).unwrap();
    root.flags[0] = 2;
    assert!(root.validate(1).is_err());
    root.flags[0] = 0;
    root.size = 100_000;
    root.allocated = 1;
    assert!(root.validate(1).is_err());
    root.allocated = 0;
    root.validate(1).unwrap();
    let old: Vec<_> = include_str!("fixtures/inode-inline-v6.hex")
        .split_whitespace()
        .map(|s| u8::from_str_radix(s, 16).unwrap())
        .collect();
    assert!(cocryptfs::format::inode::InodeBody::decode(&old).is_err());
}
