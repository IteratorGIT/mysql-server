#include "link_sec.h"
#include <cstring>
Link::Link()
{
    head=NULL;
    tail=NULL;
    num=0;
}

/**********************************************
 * 函数功能：搜索给定的密级所在的节点
 * 参数：给定的密级字符串指针， 及字符长度
 * 返回值：搜索成功则返回节点指针，否则返回NULL
 * 注意：使用字符串比较时，必须使用给定长度的字符
 ************************************************/
LINK_PTR Link::search(const char* level, uint len)
{
    LINK_PTR p=head;

    if(level==NULL)
    {
        error="The level pointer is NULL";
        return NULL;
    }

    while(p)
    {
        // 如果是 node类型的  执行空语句
        if(p->is_node_ptr)
			;
		else if( memcmp(p->u.level, p->length, level, len) == 0 )
			return p;
        else 
			p=p->child;
    }

    error="The level doesn't exist";
	return NULL;
}

LINK_PTR Link::search(struct tree_node *node)
{
	LINK_PTR p=head;
	while( p )
	{
		if( p->u.node == node )
			return p;
		p = p->child;
	}
	return NULL;
}
/***************************************
 * 函数功能：在链表尾部插入一个节点
 * 参数：节点结构体指针
 * 返回值：是否插入成功
 * 注意：插入成功后要修改tail的值
 * 最后一个节点的next值要置空，
 * 第一个节点的双亲值置空
 *************************************/
bool Link::push(LINK_PTR node)
{
    LINK_PTR p = node;

    if(node==NULL)
    {
        return false;
    }

    if((head==NULL)&&(tail==NULL))
    {
        head=p;
        tail=p;
        head->parent=NULL;
        tail->child=NULL;
    }
    else
    {
        tail->child=p;
        p->parent=tail;
        p->child=NULL;
        tail=p;
    }

    num++;

    return true;
}

/*****************************************************
* 函数功能：在给定的双亲节点之后插入一个节点
* 参数：双亲节点，需要插入的节点
* 返回值：是否插入成功
* 注意：插入前需要检查给定的子节点是否是尾节点
*******************************************************/
bool Link::insert(LINK_PTR parent, LINK_PTR node)
{
    LINK_PTR p = node;
    if(head){
	    LINK_PTR phead = head;
        while(phead != NULL){
            if( memcmp(p->u.level, p->length, phead->u.level, phead->length) == 0 ){return false;}
            phead = phead->child;
        }
    }

    if(parent==NULL && head )
    {
        return false;
    }
    else if(node==NULL)
    {
        return false;
    }

	if( !parent && !head )
	{
		head = p;
		tail = p;
		head->parent = NULL;
		head->child = NULL;
	}
    else if(parent==tail)
    {
        parent->child=p;
        p->parent=parent;
		p->child = NULL;
        tail=p;
    }
    else
    {
        p->parent=parent;
        p->child=parent->child;
        parent->child=p;
		/*if( parent->child )
			parent->child->parent=p; */
		p->child->parent = p;
    }

    num++;
    return true;
}

/**********************************************************
 * 函数功能：删除给定的节点
 * 参数：给定节点的指针
 * 返回值：指针是否删除成功
 * 注意：对于删除首节点和尾节点要修改head或tail的值
 *********************************************************/
bool Link::Delete(LINK_PTR node)
{
    if(node==NULL)
    {
        return false;
    }

    if(node==head)//如果要删除头节点
    {
        head=node->child;
        if( head == NULL )
            tail = NULL;
        else
            head->parent=NULL;
        //free(node);
        delete node;
    }
    else if(node==tail)//如果要删除尾节点
    {
        tail=node->parent;
        if( tail == NULL )
            head = NULL;
        else
            tail->child=NULL;
        //free(node);
        delete node;
    }
    else
    {
        node->parent->child=node->child;
        node->child->parent=node->parent;
        //free(node);
        delete node;
    }
    num--;//数量减少1
    return true;
}

/**********************************************************
 * 函数功能：搜索第n个节点
 * 参数：给定节点的序号
 * 返回值：搜索成功则返回节点指针，否则返回NULL
 *********************************************************/
LINK_PTR Link::get_node(uint n)
{
    unsigned int i;
    LINK_PTR p=head;

    if(n>num)
    {
        error="n is bigger then the number of node";
        return NULL;
    }
    else
    {
        for(i=0;i<n;i++)
        {
			p=p->child;
        }
    }

    return p;
}

/**********************************************************
 * 函数功能：判断该节点是否是尾结点
 * 参数：给定的密级字符串指针， 及字符长度
 * 返回值：是尾结点返回true，否则返回false
 *********************************************************/
bool Link::is_tail(const char* level, uint len){

	if( tail == NULL )
    {
        return true;
    }
    else
    {
        if( memcmp(level, len, tail->u.level, tail->length) == 0 )
        {
           return true;
        }
        else
        {
            return false;
        }
    }
}


LINK_PTR Link::create_node(const char* data, uint len)
{
	LINK_PTR node = new LINK_NODE;
	if( node == NULL )
		return NULL;
	node->child = NULL;
	node->parent = NULL;
	node->length = len;
	node->is_node_ptr = false;
	node->u.level = new char[ len + 1];
    memset(node->u.level,'\0',sizeof(char)*(len+1));
	for(uint i=0; i<len; i++)
		node->u.level[i] = data[i];
	//memcpy(node->u.level, data, len);
	return node;
}

/************************************
 * 比较两个字符串是否相同
 *************************************/
int Link::memcmp(const char* ch1, uint len1, const char* ch2, uint len2 )
{

	if( !ch1 || !ch2 )
		return -1;

	if(len1 != len2)
		return 1;
	for(unsigned int i=0; i<len1; i++)
		if(ch1[i] != ch2[i])
			return 1;
	return 0;
}

bool Link::isFather(LINK_PTR father, LINK_PTR son)
{
	if( !father || !son )
		return false;
	while( son->parent )
	{
		if( father == son->parent )
			return true;
		son = son->parent;
	}
	return false;
}

void Link::drop_link()
{
    LINK_PTR next;
    for(; head != NULL; head = next )
    {
        next = head->child;
        delete head;
    }
    tail = NULL;
    num = 0;
}


