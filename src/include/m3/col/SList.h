/*
 * Copyright (C) 2015, Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
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

#pragma once

#include <m3/Common.h>
#include <assert.h>

namespace m3 {

template<class T>
class SList;
template<class T, class It>
class SListIteratorBase;

/**
 * A listitem for the singly linked list. It is intended that you inherit from this class to add
 * data to the item.
 */
class SListItem {
    template<class T>
    friend class SList;
    template<class T, class It>
    friend class SListIteratorBase;

public:
    /**
     * Constructor
     */
    explicit SListItem() : _next() {
    }

private:
    SListItem *next() {
        return _next;
    }
    void next(SListItem *i) {
        _next = i;
    }

    SListItem *_next;
};

/**
 * Generic iterator for a singly linked list. Expects the list node class to have a next() method.
 */
template<class T, class It>
class SListIteratorBase {
public:
    explicit SListIteratorBase(T *n = nullptr) : _n(n) {
    }

    It& operator++() {
        _n = static_cast<T*>(_n->next());
        return static_cast<It&>(*this);
    }
    It operator++(int) {
        It tmp(static_cast<It&>(*this));
        operator++();
        return tmp;
    }
    bool operator==(const It& rhs) const {
        return _n == rhs._n;
    }
    bool operator!=(const It& rhs) const {
        return _n != rhs._n;
    }

protected:
    T *_n;
};

template<class T>
class SListIterator : public SListIteratorBase<T, SListIterator<T> > {
public:
    explicit SListIterator(T *n = nullptr) : SListIteratorBase<T, SListIterator<T> >(n) {
    }

    T & operator*() const {
        return *this->_n;
    }
    T *operator->() const {
        return &operator*();
    }
};

template<class T>
class SListConstIterator : public SListIteratorBase<T, SListConstIterator<T> > {
public:
    explicit SListConstIterator(T *n = nullptr) : SListIteratorBase<T, SListConstIterator<T> >(n) {
    }

    const T & operator*() const {
        return *this->_n;
    }
    const T *operator->() const {
        return &operator*();
    }
};

/**
 * The singly linked list. Takes an arbitrary class as list-item and expects it to have a prev(),
 * prev(T*), next() and next(*T) method. In most cases, you should inherit from SListItem and
 * specify your class for T.
 */
template<class T>
class SList {
public:
    using iterator          = SListIterator<T>;
    using const_iterator    = SListConstIterator<T>;

    /**
     * Constructor. Creates an empty list
     */
    explicit SList() : _head(nullptr), _tail(nullptr), _len(0) {
    }

    /**
     * Move-constructor
     */
    SList(SList<T> &&l) : _head(l._head), _tail(l._tail), _len(l._len) {
        l._head = nullptr;
        l._tail = nullptr;
        l._len = 0;
    }

    /**
     * @return the number of items in the list
     */
    size_t length() const {
        return _len;
    }

    /**
     * @return beginning of list (you can change the list items)
     */
    iterator begin() {
        return iterator(_head);
    }
    /**
     * @return end of list
     */
    iterator end() {
        return iterator();
    }
    /**
     * @return tail of the list, i.e. the last valid item
     */
    iterator tail() {
        return iterator(_tail);
    }

    /**
     * @return beginning of list (you can NOT change the list items)
     */
    const_iterator begin() const {
        return const_iterator(_head);
    }
    /**
     * @return end of list
     */
    const_iterator end() const {
        return const_iterator();
    }
    /**
     * @return tail of the list, i.e. the last valid item (NOT changeable)
     */
    const_iterator tail() const {
        return const_iterator(_tail);
    }

    /**
     * Appends the given item to the list. This works in constant time.
     *
     * @param e the list item
     * @return the position where it has been inserted
     */
    iterator append(T *e) {
        if(_head == nullptr)
            _head = e;
        else
            _tail->next(e);
        _tail = e;
        e->next(nullptr);
        _len++;
        return iterator(e);
    }
    /**
     * Inserts the given item into the list after <p>. This works in constant time.
     *
     * @param p the previous item (p = insert it at the beginning)
     * @param e the list item
     * @return the position where it has been inserted
     */
    iterator insert(T *p, T *e) {
        e->next(p ? p->next() : _head);
        if(p)
            p->next(e);
        else
            _head = e;
        if(!e->next())
            _tail = e;
        _len++;
        return iterator(e);
    }
    /**
     * Removes the first item from the list
     *
     * @return the removed item (or 0 if there is none)
     */
    T *remove_first() {
        if(_len == 0)
            return 0;
        T *res = _head;
        _head = static_cast<T*>(_head->next());
        if(_head == 0)
            _tail = 0;
        _len--;
        return res;
    }
    /**
     * Removes the given item from the list. This works in linear time.
     * Does NOT expect that the item is in the list!
     *
     * @param e the list item
     * @return true if the item has been found and removed
     */
    bool remove(T *e) {
        T *t = _head, *p = nullptr;
        while(t && t != e) {
            p = t;
            t = static_cast<T*>(t->next());
        }
        if(!t)
            return false;
        if(p)
            p->next(e->next());
        else
            _head = static_cast<T*>(e->next());
        if(!e->next())
            _tail = p;
        _len--;
        return true;
    }
    /**
     * Removes all items from the list
     */
    void remove_all() {
        _head = nullptr;
        _tail = nullptr;
        _len = 0;
    }

private:
    T *_head;
    T *_tail;
    size_t _len;
};

}
