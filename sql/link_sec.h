/****************************************************************
 * 此头文件申明了链表的模型，包括链表节点的基本结构体组成
 * 和链表应该实现的方法，以及每个方法的具体要求。在编写过
 * 程中要严格注意指针的使用，对于任何要使用的指针，有必要
 * 检查是否为空，对于错误之处要给出详细的错误信息。对于所
 * 有方法的参数，在使用前应该检查参数的合法性。
 * 对于所有申请的栈空间在不使用时需要释放，避免内存溢出。
 * 对于源码在必要处要给出详细的注释。
 * 如果需要使用windows库，需要在使用前加上编译开关，并且
 * 找到linux下对应的方法供编译器选择。
 ****************************************************************/
#ifndef LEVEL_LINK_H
#define LEVEL_LINK_H
#include <stdio.h>
#include <string>
#include <string.h>
#include <stdlib.h>
#define Link Link_sec
#define link_node link_sec_node
#include <vector>
using std::vector;
using std::string;
//范畴集树的子节点，会在tree.h中给出定义
//这里只是申明，便以后面使用
struct tree_node;

/******************************************************
 * 定义链表的节点，节点可能是一棵树的子节点的地址
 * 也有可能是密级（字符串），所以使用一个联合体存储
 * 内部有一个bool变量注明联合体中存放的是子节点指针
 * 还是字符串指针
 * ****************************************************/
struct link_node
{
	union
	{
		struct tree_node *node;//子节点结构体指针string
		char* level;	//密级字符串
	}u;
	bool is_node_ptr;		//true代表是子节点指针，否则是指针字符串
	unsigned int length;	//字符串的长度,不包含结束符
	struct link_node* child;	//指向下一个节点
	struct link_node* parent;	//指向双亲节点

	//增加一个对析构的处理
	~link_node()
	{
		// 如果是对level的指针 
		if(is_node_ptr == false && u.level != NULL) 
			delete[] u.level;
	}
};

typedef struct link_node LINK_NODE;
typedef struct link_node* LINK_PTR;
typedef unsigned int uint;

struct brim
{
    string uper;
    string lower;
};
typedef struct brim BRIM;

/***********************************************************
 * 这里只定义了必须实现的方法，对于实现过程中需要使用
 * 的其他方法，自己加入申明
 **********************************************************/
class Link
{
private:
	LINK_PTR head;	//链表的首地址
	LINK_PTR tail;	//链表的尾地址
	string error;	//存放调用方法过程中遇到的错误信息
public:
	uint num;			//链表中节点的个数
	Link();
	string get_error(){ return error;}
	/**********************************************
	 * 函数功能：搜索给定的密级所在的节点
	 * 参数：给定的密级字符串指针， 及字符长度
	 * 返回值：搜索成功则返回节点指针，否则返回NULL
	 * 注意：使用字符串比较时，必须使用给定长度的字符
	 ************************************************/
	LINK_PTR search(const char* level, uint len);
	LINK_PTR search(struct tree_node *node);

	/***************************************
	 * 函数功能：在链表尾部插入一个节点
	 * 参数：节点结构体指针
	 * 返回值：是否插入成功
	 * 注意：插入成功后要修改tail的值
	 * 最后一个节点的next值要置空，
	 * 第一个节点的双亲值置空
	 *************************************/
	bool push(LINK_PTR node);

	/*****************************************************
	 * 函数功能：在给定的双亲节点之后插入一个节点
	 * 参数：双亲节点，需要插入的节点
	 * 返回值：是否插入成功
	 * 注意：插入前需要检查给定的子节点是否是尾节点
	 *******************************************************/
	bool insert(LINK_PTR parent, LINK_PTR node);

	/**********************************************************
	 * 函数功能：删除给定的节点
	 * 参数：给定节点的指针
	 * 返回值：指针是否删除成功
	 * 注意：对于删除首节点和尾节点要修改head或tail的值
	 *********************************************************/
	bool Delete(LINK_PTR node);

	/**********************************************************
	 * 函数功能：搜索第n个节点
	 * 参数：给定节点的序号
	 * 返回值：搜索成功则返回节点指针，否则返回NULL
	 *********************************************************/
	LINK_PTR get_node(uint n);

	/**********************************************************
	 * 函数功能：判断该节点是否是尾结点
	 * 参数：给定的密级字符串指针， 及字符长度
	 * 返回值：是尾结点返回true，否则返回false
	 *********************************************************/
	bool is_tail(const char* level, uint len);

	LINK_PTR create_node(const char* data, uint len);

	bool isFather(LINK_PTR father, LINK_PTR son);
	//比较两个字符串是否相同
	int memcmp(const char* ch1, uint len1, const char* ch2, uint len2 );
	bool empty(){return !num;}
	// 清除整个链表
	void drop_link();
};

#endif		//LEVEL_LINK_H
