/****************************************************************
 * 此头文件申明了树的模型，包括树节点的基本结构体组成
 * 和树应该实现的方法，以及每个方法的具体要求。在编写过
 * 程中要严格注意指针的使用，对于任何要使用的指针，有必要
 * 检查是否为空，对于错误之处要给出详细的错误信息。对于所
 * 有方法的参数，在使用前应该检查参数的合法性。
 * 对于所有申请的栈空间在不使用时需要释放，避免内存溢出。
 * 对于源码在必要处要给出详细的注释。
 * 如果需要使用windows库，需要在使用前加上编译开关，并且
 * 找到linux下对应的方法供编译器选择。
 ****************************************************************/
#ifndef DOMAIN_TREE_H
#define DOMAIN_TREE_H
#include "link_sec.h"


/******************************************************
 * 定义树的节点
 * 节点包括范畴名、范畴长度
 * 以及父子节点的指针
 * ****************************************************/
struct tree_node
{
	char* domain;	//范畴名
	uint length;					//范畴长度
	Link* children;		//子节点
	struct tree_node* parent;	//父节点

	~tree_node()
	{
		//父节点不用管
		//如果存的有domain信息
		if(domain != NULL && length != 0 ) 
			delete[] domain;		
	}
};

typedef struct tree_node TREE_NODE;
typedef struct tree_node* TREE_PTR;

/***********************************************************
 * 这里只定义了必须实现的方法，对于实现过程中需要使用
 * 的其他方法，自己加入申明
 **********************************************************/
class DomainTree
{
private:
	TREE_PTR root;
	string error;
public:
	DomainTree();
	~DomainTree();
	/****************************************************
	 * 函数功能：递归查找给定的字符串所在的节点
	 * 参数：子树根节点：root
	 *				欲查找的字符串：domain
	 * 返回值：查找成功则返回节点指针，否则返回NULL
	 ****************************************************/
	TREE_PTR search(const char* domain, uint len);

	/******************************************************
	 * 函数功能：插入一个节点到指定的节点之后
	 * 参数：要插入的节点：node
	 *				父节点：parent
	 * 返回值：是否插入成功
	 * 注意：若参数parent为NULL，并且root为NULL时
	 *			才表示初始化空树
	 ****************************************************/
	bool insert(TREE_PTR parent, TREE_PTR node);

	/****************************************
	 * 函数功能：删除给定节点
	 * 参数：给定的节点：node
	 * 返回值：是否删除成功
	 * 注意：当树只剩根节点时才能删除根
	 *		节点，否则不能删除，其他节点删除
	 *		后要保持偏序关系
	 ********************************************/
	bool Delete(TREE_PTR node);
	bool isFather(TREE_PTR father, TREE_PTR son);
	TREE_PTR create_node(const char* data, uint len);
	bool empty(){return !root;}

private:
	TREE_PTR search(TREE_PTR root,const char* domain, uint len);
	//??????????????????
	int memcmp(const char* ch1, uint len1, const char* ch2, uint len2 );

	
};

#endif		//DOMAIN_TREE_H
