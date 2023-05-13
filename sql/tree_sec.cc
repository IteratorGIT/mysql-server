#include "tree_sec.h"
#include <cstring>
//#define CHECK_NULL(ptr, message) if( ptr == NULL ){error += message;return 0;}else;
#define CHECK_NULL(ptr, message) if( ptr == NULL ){error += message;return 0;}
DomainTree::DomainTree()
{
	root = NULL;
}

DomainTree::~DomainTree()
{

}

TREE_PTR DomainTree::search(const char* domain, uint len)
{
	CHECK_NULL(root, "search: this a empty tree");
	CHECK_NULL(domain, "search: empty domain");
	TREE_PTR ret = search(root, domain, len);
	return ret;
}

/******************************************************
 * 函数功能：插入一个节点到指定的节点之后
 * 参数：要插入的节点：node
 *				父节点：parent
 * 返回值：是否插入成功
 * 注意：若参数parent为NULL，并且root为NULL时
 *			才表示初始化空树
 ****************************************************/
bool DomainTree::insert(TREE_PTR parent, TREE_PTR node)
{
	//参数检查
 	CHECK_NULL(node, "insert: the node ptr is NULL");
	//申请子节点空间
	TREE_PTR new_node = node;
	
	//建立空树
	if( parent == NULL && root == NULL )
	{
		root = new_node;
		new_node->parent = NULL;
		return true;
	}
	//插入子节点
	CHECK_NULL(parent, "insert: parent ptr is NULL");
	/* 生成链表节点
	 * 注意新节点中的其他指针未初始化*/
	struct link_node *node_backup = new struct link_node;
	node_backup->is_node_ptr = true;
	node_backup->u.node = new_node;
	//新增加一个子节点
	if( !parent->children )
		parent->children = new Link();
	bool state = parent->children->push(node_backup);
	if( state == false ) error = parent->children->get_error();
	new_node->parent = parent;
	return state;
}

/****************************************************
 * 函数功能：递归查找给定的字符串所在的节点
 * 参数：子树根节点：root
 *				欲查找的字符串：domain
 * 返回值：查找成功则返回节点指针，否则返回NULL
 ****************************************************/
TREE_PTR DomainTree::search(TREE_PTR root,const char* domain, uint len)
{
	//检查节点
	if( root == NULL ) return NULL;
	//检查是否是要查找的范畴
	if( memcmp(domain, len, root->domain, root->length) == 0)
		return root;
	//检查是否有子节点
	if( !root->children )
		return NULL;
	//递归查找所有子树节点
	TREE_PTR ret;
	if(root->children)
	for(uint i=0; i<root->children->num; i++)
	{
		ret = search(root->children->get_node(i)->u.node, domain, len);
		if( ret )
			return ret;
	}
	return NULL;
}

/************************************
 * 函数功能：比较两个字符串是否相同
 * 参数：两个字符串指针，及字符长度
 * 返回值：-1表示比较出错
 *					0表示相同
 *					1表示不同
 *************************************/
int DomainTree::memcmp(const char* ch1, uint len1, const char* ch2, uint len2 )
{
	//参数检查
	if( !ch1 || !ch2 )
		return -1;
	//长度不同则一定不等
	if(len1 != len2)
		return 1;
	//逐位比较
	for(uint i=0; i<len1; i++)
		if(ch1[i] != ch2[i])
			return 1;
	return 0;
}

/****************************************
 * 函数功能：删除给定节点
 * 参数：给定的节点：node
 * 返回值：是否删除成功
 * 注意：当树只剩根节点时才能删除根
 *		节点，否则不能删除。
 * 如果当前结点还存在子节点，则直接删除失败 
 ********************************************/
bool DomainTree::Delete(TREE_PTR node)
{
	CHECK_NULL(node, "Delete: node is NULL");
	/* 当删除的是根节点，并且根节点有子节点
	 * 时拒绝删除节点*/
	if(node == root && root->children)
		return false;
	/* 当删除的是根节点，同时根节点无
	 * 子节点时，可以删除*/
	if( node==root && !root->children )
	{
		delete root;
		root = NULL;
		return true;
	}
	
	/* 20210728修改：如果当前结点还存在子节点，则直接删除失败。*/
    if(node->children){
        error="The node has child nodes, so it cannot be deleted.";
        return false;
	}
	
    node->parent->children->Delete( node->parent->children->search(node) );

	if(node->parent->children->num == 0) 
	{
		//先释放 再置空
		delete node->parent->children;
		node->parent->children =NULL;
	}

    delete node;
    return true;
}

bool DomainTree::isFather(TREE_PTR father, TREE_PTR son)
{
	CHECK_NULL(father, "father is NULL");
	CHECK_NULL(son, "son is NULL");
	while( son->parent )
	{
		if( father == son->parent )
			return true;
		son = son->parent;
	}
	return false;
}

TREE_PTR DomainTree::create_node(const char* data, uint len)
{
	TREE_PTR node = new TREE_NODE;
	if( !node ) return NULL;
	node->children = NULL;
	node->domain = new char[ len +1];
	memset(node->domain,'\0',sizeof(char)*(len+1));
	node->length = len;
	if( !node->domain ) return NULL;
	for(uint i=0; i<len; i++)
		node->domain[i] = data[i];
	node->parent = NULL;
	return node;
}

