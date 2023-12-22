//===-- trec_map.h -------------------------------------*- C++ -*-===//
//-*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of TraceRecorder (TRec), a race detector.
//
//===----------------------------------------------------------------------===//

#ifndef TREC_MAP_H
#define TREC_MAP_H

namespace __trec {

template <typename K, typename V>
struct MyPair {
    K key;
    V value;
};

enum COLOR
{
	BLACK,
	RED
};

template <class V>
struct RBTreeNode
{
	RBTreeNode<V>* _parent; //父节点
	RBTreeNode<V>* _left; //左孩子
	RBTreeNode<V>* _right; //右孩子
	V _val;
	COLOR _color; //颜色

	RBTreeNode(const V& val = V())
		:_parent(nullptr)
		, _left(nullptr)
		, _right(nullptr)
		, _val(val)
		, _color(RED)
	{}
};

template <class  V>
struct RBTreeIterator
{
	typedef RBTreeNode<V> Node;
	typedef RBTreeIterator<V> Self;
	Node* _node;

	RBTreeIterator(Node* node)
		:_node(node)
	{}

	//解引用
	V& operator*()
	{
		return _node->_val;
	}

	V* operator->()
	{
		return &_node->_val;
	}

	bool operator!=(const Self& it)
	{
		return _node != it._node;
	}

	Self& operator++()
	{
		if (_node->_right) //存在右节点
		{
			//右子树的最左结点
			_node = _node->_right;
			while (_node->_left)
			{
				_node = _node->_left;
			}
		}
		else //不存在右节点
		{
			Node* parent = _node->_parent;
			while (_node == parent->_right)//回溯
			{
				_node = parent;
				parent = parent->_parent;
			}
			//特殊情况：根节点没有右孩子，则不需要更新结点
			if (_node->_right != parent) 
				_node = parent;
		}
		return *this;
	}
};


template <class K, class V, class KeyOfValue>
class RBTree
{
public:
	typedef RBTreeNode<V> Node;

	RBTree()
		:_header(new Node)
	{
		//创建空树
		_header->_left = _header->_right = _header;
	}

	RBTreeNode<V>* find(const K& key) const
	{
		Node* cur = _header->_parent;
		KeyOfValue kov;

		// 从根节点开始查找
		while (cur)
		{
			// 如果找到对应的键，则返回该节点
			if (kov(cur->_val) == key)
				return cur;
			// 如果当前节点的键大于要查找的键，则在左子树中继续查找
			else if (kov(cur->_val) > key)
				cur = cur->_left;
			// 否则在右子树中继续查找
			else
				cur = cur->_right;
		}

		// 如果未找到对应键的节点，则返回空指针
		return nullptr;
	}

	void swap(Node** cur, Node** parent) {
        Node* temp = *cur;
        *cur = *parent;
        *parent = temp;
    }
	bool insert(const V& val)
	{
		if (_header->_parent == nullptr)
		{
			Node* root = new Node(val);

			_header->_parent = root;
			root->_parent = _header;
			_header->_left = _header->_right = root;

			//根节点为黑色
			root->_color = BLACK;
			return true;
		}

		Node* cur = _header->_parent;
		Node* parent = nullptr;

		KeyOfValue kov;
		//1.寻找到要插入的结点的位置
		while (cur)
		{
			parent = cur;
			if (kov(cur->_val) == kov(val))
				return false;
			else if (kov(cur->_val) > kov(val))
				cur = cur->_left;
			else
				cur = cur->_right;
		}
		//2.创建节点
		cur = new Node(val);
		if (kov(parent->_val) > kov(cur->_val))
			parent->_left = cur;
		else
			parent->_right = cur;
		cur->_parent = parent;

		//3.颜色的修改或者结构的调整
		while (cur != _header->_parent && cur->_parent->_color == RED)//不为根且存在连续红色，则需要调整
		{
			parent = cur->_parent;
			Node* gfather = parent->_parent;

			if (gfather->_left == parent)
			{
				Node* uncle = gfather->_right;
				//情况1.uncle存在且为红
				if (uncle && uncle->_color == RED)
				{
					parent->_color = uncle->_color = BLACK;
					gfather->_color = RED;
					//向上追溯
					cur = gfather;
				}
				else
				{
					if (parent->_right == cur)//情况3
					{
						RotateL(parent);
						swap(&cur, &parent);
					}
					//情况2.uncle不存在或者uncle为黑
					RotateR(gfather);
					parent->_color = BLACK;
					gfather->_color = RED;
					break;
				}
			}
			else
			{
				Node* uncle = gfather->_left;
				if (uncle && uncle->_color == RED)
				{
					parent->_color = uncle->_color = BLACK;
					gfather->_color = RED;
					//向上追溯
					cur = gfather;
				}
				else
				{
					if (parent->_left == cur)
					{
						RotateR(parent);
						swap(&cur, &parent);
					}

					RotateL(gfather);
					parent->_color = BLACK;
					gfather->_color = RED;
					break;
				}
			}
		}

		//根节点为黑色
		_header->_parent->_color = BLACK;
		//更新头结点的左右指向
		_header->_left = leftMost();
		_header->_right = rightMost();
		return true;
	}

	void RotateL(Node* parent)
	{
		Node* subR = parent->_right;
		Node* subRL = subR->_left;

		parent->_right = subRL;
		if (subRL)
			subRL->_parent = parent;
		if (parent == _header->_parent)
		{
			_header->_parent = subR;
			subR->_parent = _header;
		}
		else
		{
			Node* gfather = parent->_parent;
			if (gfather->_left == parent)
				gfather->_left = subR;
			else
				gfather->_right = subR;
			subR->_parent = gfather;
		}
		subR->_left = parent;
		parent->_parent = subR;
	}

	void RotateR(Node* parent)
	{
		Node* subL = parent->_left;
		Node* subLR = subL->_right;

		parent->_left = subLR;
		if (subLR)
			subLR->_parent = parent;

		if (parent == _header->_parent)
		{
			_header->_parent = subL;
			subL->_parent = _header;
		}
		else
		{
			Node* gfather = parent->_parent;
			if (gfather->_left == parent)
				gfather->_left = subL;
			else
				gfather->_right = subL;
			subL->_parent = gfather;
		}
		subL->_right = parent;
		parent->_parent = subL;
	}

	Node* leftMost()
	{
		Node* cur = _header->_parent;
		while (cur && cur->_left)
		{
			cur = cur->_left;
		}
		return cur;
	}

	Node* rightMost()
	{
		Node* cur = _header->_parent;
		while (cur && cur->_right)
		{
			cur = cur->_right;
		}
		return cur;
	}
	
	typedef RBTreeIterator<V> iterator;

	iterator begin()
	{
		return iterator(_header->_left);
	}
	iterator end()
	{
		return iterator(_header);
	}

private:
	Node* _header;
};

template<class K, class T>
class Map
{
	struct MapKeyOfValue
	{
		const K& operator()(const MyPair<K, T>& val)
		{
			return val.key;
		}
	};
public:
	bool insert(const MyPair<K, T>& kv)
	{
		return _rbt.insert(kv);
	}
	
	//T& operator[](const K& key)
	//{
	//	bool ret = _rbt.insert(make_pair(key, T()));
	//}

    T& operator[](const K& key) const {
        typename RBTree<K, MyPair<K, T>, MapKeyOfValue>::Node* node = _rbt.find(key);
        
        // 如果找到了节点，则返回节点的值
        if (node) {
            return node->_val.value;
        }
        // 实现按键访问值的逻辑（对于const对象）
    }

    typedef typename RBTree<K, MyPair<K, T>, MapKeyOfValue>::iterator iterator;

	iterator begin()
	{
		return _rbt.begin();
	}
	iterator end()
	{
		return _rbt.end();
	}

private:
	typedef RBTree<K, MyPair<K, T>, MapKeyOfValue> rbt;
	rbt _rbt;
};

} // namespace __trec

#endif  // #ifndef TREC_MAP_H