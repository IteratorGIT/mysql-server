#include "sec_sign.h"
#include "stdlib.h"

//新建链表
Link *level_link = new Link();
//新建范畴树
DomainTree *domain_tree = new DomainTree();


int levelcmp(const char* level1, uint len1,
						 const char* level2, uint len2)
{
	LINK_PTR temp_node1=NULL, temp_node2=NULL;
	
	if((temp_node1 = level_link->search(level1,len1)) != NULL)
		{
			if((temp_node2 = level_link->search(level2,len2)) != NULL)
				{
					if(temp_node1 == temp_node2) 
						return 0;
					if( level_link->isFather( temp_node1, temp_node2 ) )
						return 1;
					if( level_link->isFather(temp_node2, temp_node1) )
						return -1;
					return -2;
				}
		}
	return -2;
}

//如果domain1 是 domain2的father return 1
int domaincmp(const char* domain1, uint len1,
							const char* domain2, uint len2)
{
	TREE_PTR temp_node1 = NULL, temp_node2 = NULL;
	
	if((temp_node1 = domain_tree->search(domain1, len1)) !=NULL)
		{
			if((temp_node2 = domain_tree->search(domain2, len2)) !=NULL)
				{
						if(temp_node1 == temp_node2)return 0;
						if( domain_tree->isFather(temp_node1, temp_node2) )
								return 1;
						if( domain_tree->isFather(temp_node2, temp_node1) )
							return -1;
						return -2;
				}
		}
	return -2;
}
	
bool add_level(const char* level_p, uint len_p, 
								 const char* level_n, uint len_n)
{
	LINK_PTR temp_p=NULL, temp_n=NULL;
	temp_p = level_link->search(level_p, len_p);

	//如果要插入的节点已经存在 也返回 false 
	if(level_link->search(level_n, len_n) != NULL)
		return false;

	//如果不存在指定的上级
	if(level_p && !temp_p )
		return false;
	
	//如果要插入的位置不是尾部
	if(!level_link->is_tail(level_p, len_p))
		return false;

	//如果创建节点失败
	if( (temp_n =level_link->create_node(level_n, len_n)) == NULL)
		return false;


	if(level_link->insert(temp_p, temp_n) == true)
		return true;
	else
		return false;
}
	
bool add_domain(const char* domain_p, uint len_p,
							  const char* domain_n, uint len_n)
{   //空树的时候指定上级 
	if( domain_p && domain_tree->empty()  )
		return false;

	TREE_PTR temp_p=NULL, temp_n=NULL;
	temp_p = domain_tree->search(domain_p, len_p);
	temp_n = domain_tree->search(domain_n, len_n);
	
	//要增加的下级已经存在
	if(temp_n != NULL) return false;
	
	//指定了不存在的上级
	if( domain_p&&!temp_p )
		return false;
	if((temp_n = domain_tree->create_node(domain_n, len_n)) == NULL)
		return false;
		
	if(domain_tree->insert(temp_p, temp_n) == true)
		return true;
	else
		return false;
} 
	
bool delete_level(const char* level_h, uint len_h,const char* level, uint len)
{
	LINK_PTR temp_l=NULL;
	LINK_PTR temp_h=NULL;
    // 如果要删除的位置不存在
	if( (temp_l = level_link->search(level, len)) == NULL)
		return false;
	
	//如果指定的上级不存在 返回false
	if( (temp_h = level_link->search(level_h, len_h)) == NULL) 
	   return false;

	//如果指定的上级下级对不存在 返回false
	if( temp_h->child==NULL || level_link->memcmp(temp_h->child->u.level,temp_h->child->length,level,len) !=0)     
	  return false;  

	//如果要删除的位置不是尾部
	if(!level_link->is_tail(level, len))
		return false;
	return(level_link->Delete(temp_l));
}
	
bool delete_domain(const char* domain, uint len)
{
	TREE_PTR temp_d = NULL;
	
	if( (temp_d = domain_tree->search(domain, len)) == NULL)
		return false;
	return(domain_tree->Delete(temp_d));
}


bool have_init()
{
	if( !domain_tree->empty() || !level_link->empty() )
		return true;
	else
		return false;
}

