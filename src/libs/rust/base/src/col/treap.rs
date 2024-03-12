/*
 * Copyright (C) 2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2019-2021 Nils Asmussen, Barkhausen Institut
 *
 * This file is part of M3 (Microkernel-based SysteM for Heterogeneous Manycores).
 *
 * M3 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * M3 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License version 2 for more details.
 */

use core::cmp::Ordering;
use core::fmt;
use core::num::Wrapping;
use core::ptr::{read_volatile, NonNull};

use crate::boxed::Box;

struct Node<K, V> {
    left: Option<NonNull<Node<K, V>>>,
    right: Option<NonNull<Node<K, V>>>,
    prio: Wrapping<u32>,
    key: K,
    value: V,
}

impl<K: Copy + Ord, V> Node<K, V> {
    fn new(key: K, value: V, prio: Wrapping<u32>) -> Self {
        Node {
            left: None,
            right: None,
            prio,
            key,
            value,
        }
    }

    fn into_value(self) -> V {
        self.value
    }
}

/// A balanced binary tree.
///
/// A treap is a combination of a binary tree and a heap. So the child-node on the left has a
/// smaller key than the parent and the child on the right has a bigger key.
///
/// Additionally the root-node has the smallest priority and it increases when walking towards the
/// leafs. The priority is "randomized" by fibonacci-hashing. This way, the tree is well balanced
/// in most cases.
///
/// The idea and parts of the implementation are taken from the [MMIX](http://mmix.cs.hm.edu/)
/// simulator, written by Donald Knuth
#[derive(Default)]
pub struct Treap<K: Copy + Ord, V> {
    root: Option<NonNull<Node<K, V>>>,
    prio: Wrapping<u32>,
}

impl<K: Copy + Ord, V> Treap<K, V> {
    /// Creates an empty treap
    pub const fn new() -> Self {
        Treap {
            root: None,
            prio: Wrapping(314_159_265),
        }
    }

    /// Returns true if the treap has no elements
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// Removes all elements from the treap
    pub fn clear(&mut self) {
        if let Some(r) = self.root.take() {
            Self::remove_rec(r);
            // destroy the node
            unsafe { drop(Box::from_raw(r.as_ptr())) };
        }

        self.prio = Wrapping(314_159_265);
    }

    fn remove_rec(node: NonNull<Node<K, V>>) {
        unsafe {
            if let Some(l) = (*node.as_ptr()).left {
                Self::remove_rec(l);
                drop(Box::from_raw(l.as_ptr()));
            }
            if let Some(r) = (*node.as_ptr()).right {
                Self::remove_rec(r);
                drop(Box::from_raw(r.as_ptr()));
            }
        }
    }

    /// Returns a reference to the value for the given key
    pub fn get(&self, key: &K) -> Option<&V> {
        self.get_node(key).map(|n| unsafe { &(*n.as_ptr()).value })
    }

    /// Returns a mutable reference to the value for the given key
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.get_node(key)
            .map(|n| unsafe { &mut (*n.as_ptr()).value })
    }

    /// Returns a mutable reference to the root value
    pub fn get_root_mut(&mut self) -> Option<&mut V> {
        unsafe {
            // FIXME the read_volatile seems to be necessary to convince the compiler to re-extract
            // the root element every time and not just once (see CapTable::revoke_all).
            // looks like a compiler bug
            read_volatile(&self.root).map(|r| &mut (*r.as_ptr()).value)
        }
    }

    fn get_node(&self, key: &K) -> Option<NonNull<Node<K, V>>> {
        let mut node = self.root;
        loop {
            match node {
                Some(n) => unsafe {
                    match key.cmp(&(*n.as_ptr()).key) {
                        Ordering::Less => node = (*n.as_ptr()).left,
                        Ordering::Greater => node = (*n.as_ptr()).right,
                        Ordering::Equal => return Some(n),
                    }
                },
                None => return None,
            }
        }
    }

    /// Inserts the given value for given key, assuming that the key does not exist in the tree and
    /// returns a mutable reference to the stored value
    #[inline(always)]
    pub fn insert(&mut self, key: K, value: V) -> &mut V {
        let node = Box::new(Node::new(key, value, self.prio));
        self.do_insert(node)
    }

    fn do_insert(&mut self, mut node: Box<Node<K, V>>) -> &mut V {
        unsafe {
            let mut q = &mut self.root;
            loop {
                match *q {
                    None => break,
                    Some(n) if (*n.as_ptr()).prio >= self.prio => break,
                    Some(n) => match node.key.cmp(&(*n.as_ptr()).key) {
                        Ordering::Less => q = &mut (*n.as_ptr()).left,
                        Ordering::Greater => q = &mut (*n.as_ptr()).right,
                        Ordering::Equal => panic!("Key does already exist"),
                    },
                }
            }

            let mut prev = *q;

            {
                // At this point we want to split the binary search tree p into two parts based on the
                // given key, forming the left and right subtrees of the new node q. The effect will be
                // as if key had been inserted before all of p’s nodes.
                let mut l = &mut node.left;
                let mut r = &mut node.right;
                loop {
                    match prev {
                        None => break,
                        Some(p) => match node.key.cmp(&(*p.as_ptr()).key) {
                            Ordering::Less => {
                                *r = Some(p);
                                r = &mut (*p.as_ptr()).left;
                                prev = *r;
                            },
                            Ordering::Greater => {
                                *l = Some(p);
                                l = &mut (*p.as_ptr()).right;
                                prev = *l;
                            },
                            Ordering::Equal => panic!("Key does already exist"),
                        },
                    }
                }
                *l = None;
                *r = None;
            }

            *q = Some(NonNull::from(Box::leak(node)));

            // fibonacci hashing to spread the priorities very even in the 32-bit room
            self.prio += Wrapping(0x9e37_79b9); // floor(2^32 / phi), with phi = golden ratio

            &mut (*q.unwrap().as_ptr()).value
        }
    }

    /// Sets the given key to given value, either by inserting a new node or by updating the value
    /// of the existing node. It returns a mutable reference to the stored value
    pub fn set(&mut self, key: K, value: V) -> &mut V {
        if let Some(n) = self.get_node(&key) {
            unsafe {
                (*n.as_ptr()).value = value;
                &mut (*n.as_ptr()).value
            }
        }
        else {
            self.insert(key, value)
        }
    }

    /// Removes the root element of the treap and returns the value
    pub fn remove_root(&mut self) -> Option<V> {
        self.root.map(|r| {
            Self::remove_from(&mut self.root, r);
            unsafe { Box::from_raw(r.as_ptr()).into_value() }
        })
    }

    /// Removes the element from the treap for the given key and returns the value
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let mut p = &mut self.root;
        loop {
            match *p {
                Some(n) => unsafe {
                    match key.cmp(&(*n.as_ptr()).key) {
                        Ordering::Less => p = &mut (*n.as_ptr()).left,
                        Ordering::Greater => p = &mut (*n.as_ptr()).right,
                        Ordering::Equal => break,
                    }
                },
                None => return None,
            }
        }

        let node = (*p).unwrap();
        Self::remove_from(p, node);
        unsafe { Some(Box::from_raw(node.as_ptr()).into_value()) }
    }

    fn remove_from(p: &mut Option<NonNull<Node<K, V>>>, node: NonNull<Node<K, V>>) {
        unsafe {
            match ((*node.as_ptr()).left, (*node.as_ptr()).right) {
                // two childs
                (Some(l), Some(r)) => {
                    // rotate with left
                    if (*l.as_ptr()).prio < (*r.as_ptr()).prio {
                        (*node.as_ptr()).left = (*l.as_ptr()).right;
                        (*l.as_ptr()).right = Some(node);
                        *p = Some(l);
                        Self::remove_from(&mut (*l.as_ptr()).right, node);
                    }
                    // rotate with right
                    else {
                        (*node.as_ptr()).right = (*r.as_ptr()).left;
                        (*r.as_ptr()).left = Some(node);
                        *p = Some(r);
                        Self::remove_from(&mut (*r.as_ptr()).left, node);
                    }
                },
                // one child: replace us with our child
                (Some(l), None) => {
                    *p = Some(l);
                },
                (None, Some(r)) => {
                    *p = Some(r);
                },
                // no child: simply remove us from parent
                (None, None) => {
                    *p = None;
                },
            }
        }
    }
}

impl<K: Copy + Ord, V> Drop for Treap<K, V> {
    fn drop(&mut self) {
        self.clear();
    }
}

fn print_rec<K, V>(node: NonNull<Node<K, V>>, f: &mut fmt::Formatter<'_>) -> fmt::Result
where
    K: Copy + Ord + fmt::Debug,
    V: fmt::Debug,
{
    let node_ptr = node.as_ptr();
    unsafe {
        writeln!(f, "  {:?} -> {:?}", (*node_ptr).key, (*node_ptr).value)?;
        if let Some(l) = (*node_ptr).left {
            print_rec(l, f)?;
        }
        if let Some(r) = (*node_ptr).right {
            print_rec(r, f)?;
        }
        Ok(())
    }
}

impl<K: Copy + Ord + fmt::Debug, V: fmt::Debug> fmt::Debug for Treap<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.root {
            Some(r) => print_rec(r, f),
            None => Ok(()),
        }
    }
}
