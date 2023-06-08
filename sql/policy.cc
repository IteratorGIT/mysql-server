#include "sql_plugin.h"                         // Includes my_global.h
#include "sql/auth/sql_acl.h"                        // fill_schema_*_privileges   sql_acl.h的位置变了，如果编译报错，可以试试改为"sql/auth/sql_acl.h"
#include "sql_select.h"                         // For select_describe
#include "sql_base.h"                       // close_tables_for_reopen
#include "sql_parse.h"             // check_access, check_table_access
#include "set_var.h"
#include "sql_list.h"                           /* List */
#include "handler.h"                            /* enum_schema_tables */
#include "table.h"                              /* enum_schema_table_state */
#include "key.h"
#include "sql_sign_manage.h"
#include "sec_sign.h"
#include "policy.h"
#include <string.h>
#include <stdlib.h>
#include "SyntaxParseAnalysis.h"
#include <dlfcn.h>
#include <math.h>
#include "log.h"
#include "sql/mysqld.h"
#include "sql_lex.h"
#include "records.h"
#include "protocol_classic.h"
//#include "sql_cache.h"            /*query_cache.flush()*/
#include "my_dbug.h"
#include "sql/sql_class.h"
#include "sql/auth/sql_auth_cache.h"

// string att_name; 
class String;
struct TABLE_LIST;
struct LEX;

vector<ATT> att_map;
vector<POLICY> policy_map;


#define CHECK_NULL(ptr)	if(ptr == NULL) \
							return true; \
						else;

#define EQUAL(LEX_STR1, LEX_STR2) ((LEX_STR1).length==(LEX_STR2).length \
					&& memcmp((LEX_STR1).str,(LEX_STR2).str,(LEX_STR1).length)==0)

ATT_TYPE get_att_type(LEX_CSTRING& type)  // 初始化的时候用到的 把表中的type string 转化为内部表示
{
	if(memcmp(type.str,"int",type.length>strlen("int")?strlen("int"):type.length)==0)
		return ATT_INT;
	if(memcmp(type.str,"double",type.length>strlen("double")?strlen("double"):type.length)==0)
		return ATT_DOUBLE;
	if(memcmp(type.str,"string",type.length>strlen("string")?strlen("string"):type.length)==0)
		return ATT_STRING;
	if(memcmp(type.str,"set",type.length>strlen("set")?strlen("set"):type.length)==0)
		return ATT_SET;
	else
		return ATT_NONE;
}

void get_att(vector<ATTS> ALL_ATTS, LEX_CSTRING& name, ATT& att)
{
    if( name.length==0)
          return;

   int len = ALL_ATTS.size();
   for(int j = 0 ;j< len;++j)
    {
      DBUG_PRINT("info", ("init attributes record"));
      ATTS tmp =   ALL_ATTS[j];
      LEX_CSTRING id_t= tmp.id_t;
      LEX_CSTRING name_t= tmp.name_t;
      LEX_CSTRING type_t= tmp.type_t;
      
      if( EQUAL(name, name_t) )
      {
          att.att_type = get_att_type(type_t);
		  break;
      }
    }

}


//从attribute_manager中读取对象-属性关系
//成功 true
//失败 false
bool init_att_map(THD* thd)
{
    // 先打开 abac_attributes 表
    ATT att;
    TABLE *table, *table_att;
    unique_ptr_destroy_only<RowIterator> iterator; 
    bool result;
    MEM_ROOT tmp_root{PSI_NOT_INSTRUMENTED, 4096};
    TABLE_LIST tables_att("mysql", "abac_attributes", TL_READ);
    
    vector<ATTS> ALL_ATTS;
    ALL_ATTS.clear();
    int read_rec_errcode;
    tables_att.open_strategy= TABLE_LIST::OPEN_NORMAL;  
    result= open_trans_system_tables_for_read(thd, &tables_att);
    // 如果表打开失败
    if (result)
    {
      //DBUG_PRINT("error",("Can't open attribute_manager table"));
      if (!opt_help) sql_print_error("Could not open mysql.attribute_manager table. "
                                    "attribute_manager may be not loaded");
      else sql_print_warning("Could not open mysql.attribute_manager table. "
                                "Some options may be missing from the help text");
      return false;
    }

    table_att = tables_att.table;
    iterator = init_table_iterator(thd, table_att, false,false);
   
    // 如果迭代器初始化失败
    if (iterator == nullptr) 
    {
       close_trans_system_tables(thd);
       return false;
    }
    table_att->use_all_columns();

    //先开始读有那些属性类型
    while (!(read_rec_errcode = iterator->Read()))
    {
      DBUG_PRINT("info", ("init attributes record"));
      String str_id, str_name, str_type;

       get_field(&tmp_root, table_att->field[0], &str_id);
       get_field(&tmp_root, table_att->field[1], &str_name);
       get_field(&tmp_root, table_att->field[2], &str_type);

      ATTS tmp;
      tmp.id_t= {(char *)str_id.ptr(), str_id.length()};
      tmp.name_t= {(char *)str_name.ptr(), str_name.length()};
      tmp.type_t= {(char *)str_type.ptr(), str_type.length()};
      ALL_ATTS.push_back(tmp);
    }
  iterator.reset();
  table_att->invalidate_dict();  // Force close to free memory
  close_trans_system_tables(thd);

    //attribute_manager 处理部分
    TABLE_LIST tables("mysql", "abac_attribute_manager", TL_READ);
    tables.open_strategy= TABLE_LIST::OPEN_NORMAL; 
    result= open_trans_system_tables_for_read(thd, &tables);
    if (result)
    {
      //DBUG_PRINT("error",("Can't open attributes table"));
      if (!opt_help) sql_print_error("Could not open mysql.attributes table. " 
                            "attributes may be not loaded");
      else sql_print_warning("Could not open mysql.attributes table. "
                          "Some options may be missing from the help text");
       return false;
    }
    table= tables.table;
    iterator  = init_table_iterator(thd,table,false,false);
    if (iterator == nullptr)
    { 
      close_trans_system_tables(thd);
      sql_print_error("Could not initialize init_read_record; attribute_manager not "
                      "loaded");
      return false;
    }

    table->use_all_columns();

    //new added by yuang in 2022.9.26 公共内存上锁
    Acl_cache_lock_guard acl_cache_lock(thd, Acl_cache_lock_mode::WRITE_MODE);
    if (!acl_cache_lock.lock()) return false;

    att_map.clear();
    while (!(read_rec_errcode = iterator->Read()))
    {
      DBUG_PRINT("info", ("init attribute_manager record"));
      String str_object, str_name, str_value;

       get_field(&tmp_root, table->field[0], &str_object);
       get_field(&tmp_root, table->field[1], &str_name);
       get_field(&tmp_root, table->field[2], &str_value);

      LEX_CSTRING object_t= {(char *)str_object.ptr(), str_object.length()};
      LEX_CSTRING name_t= {(char *)str_name.ptr(), str_name.length()};
      LEX_CSTRING value_t= {(char *)str_value.ptr(), str_value.length()};
      
	  att.object = object_t.str;
	  att.att_value = value_t.str;
      att.att_name = name_t.str;
      get_att(ALL_ATTS, name_t, att);
	  att_map.push_back(att);
    }
    
    //new added by yuang in 2022.9.26 公共内存解锁
    acl_cache_lock.unlock();

    iterator.reset();
    table->invalidate_dict();
    close_trans_system_tables(thd);
    return true;
}

//成功 true
//失败 false
bool init_policy_map(THD* thd)
{
    POLICY policy;
    //TABLE_LIST tables;
    TABLE *table;
    // READ_RECORD read_record_info;
    unique_ptr_destroy_only<RowIterator> iterator; 
    bool result;
    MEM_ROOT tmp_root{PSI_NOT_INSTRUMENTED, 4096};
    TABLE_LIST tables("mysql", "abac_policies", TL_READ);

    tables.open_strategy= TABLE_LIST::OPEN_NORMAL;

    // result= open_and_lock_tables(thd, &tables, FALSE, MYSQL_LOCK_IGNORE_TIMEOUT);
    result= open_trans_system_tables_for_read(thd, &tables);
    if (result)
    {
      //DBUG_PRINT("error",("Can't open policys table"));
      if (!opt_help) sql_print_error("Could not open mysql.policys table. "
                            "policys may be not loaded");
      else sql_print_warning("Could not open mysql.policys table. "
                          "Some options may be missing from the help text");
      return false;
    }
    table= tables.table;

    iterator  = init_table_iterator(thd,table,false,false);
    if (iterator == nullptr)
    { close_trans_system_tables(thd);
      sql_print_error("Could not initialize init_read_record; policys not "
                      "loaded");
      return false;
    }
    table->use_all_columns();


    //new added by yuang in 2022.9.26 公共内存上锁
    Acl_cache_lock_guard acl_cache_lock(thd, Acl_cache_lock_mode::WRITE_MODE);
    if (!acl_cache_lock.lock()) return false;

    policy_map.clear();
    int read_rec_errcode;

    while (!(read_rec_errcode = iterator->Read()))
    {
        DBUG_PRINT("info", ("init policys record"));
        
        String policy_enable;  
        get_field(&tmp_root, table->field[12], &policy_enable); 
        if(strncmp((char *)policy_enable.ptr(), "1", policy_enable.length()) == 0)
        {
            policy.subject.clear();
            policy.object.clear();
            policy.object_type.clear();
            policy.left.clear();
            policy.oper.clear();
            policy.right.clear();
            policy.name.clear();

            String str_subject, str_object,str_object_type, str_action;
            String poli_name;
            String policy_att_name, policy_const_val, policy_operator, policy_tag;
            get_field(&tmp_root, table->field[0], &str_subject);
            get_field(&tmp_root, table->field[1], &str_object);
            get_field(&tmp_root, table->field[2], &str_object_type);
            get_field(&tmp_root, table->field[3], &str_action);
            get_field(&tmp_root, table->field[4], &poli_name);
            get_field(&tmp_root, table->field[6], &policy_att_name); 
            get_field(&tmp_root, table->field[7], &policy_const_val); 
            get_field(&tmp_root, table->field[8], &policy_operator); 
            get_field(&tmp_root, table->field[9], &policy_tag); 
            if(strncmp((char *)policy_operator.ptr(), "contain", policy_operator.length()) == 0)
            {
                if(strncmp((char *)policy_tag.ptr(), "AttValAttval", policy_tag.length()) == 0)
                {
                    policy.left.append("O.");
                    policy.left.append(policy_att_name.ptr(), policy_att_name.length());
                    policy.oper.append("in");
                    policy.right.append("S.");
                    policy.right.append(policy_att_name.ptr(), policy_att_name.length());
                }
                else if(strncmp((char *)policy_tag.ptr(), "AttValConstVal", policy_tag.length()) == 0)
                {
                    policy.left.append(policy_const_val.ptr(), policy_const_val.length());
                    policy.oper.append("in");
                    policy.right.append("S.");
                    policy.right.append(policy_att_name.ptr(), policy_att_name.length());
                }
            }
            else if(strncmp((char *)policy_operator.ptr(), "uncontain", policy_operator.length()) == 0)
            {
                if(strncmp((char *)policy_tag.ptr(), "AttValAttval", policy_tag.length()) == 0)
                {
                    policy.left.append("O.");
                    policy.left.append(policy_att_name.ptr(), policy_att_name.length());
                    policy.oper.append("notin");
                    policy.right.append("S.");
                    policy.right.append(policy_att_name.ptr(), policy_att_name.length());
                }
                else if(strncmp((char *)policy_tag.ptr(), "AttValConstVal", policy_tag.length()) == 0)
                {
                    policy.left.append(policy_const_val.ptr(), policy_const_val.length());
                    policy.oper.append("notin");
                    policy.right.append("S.");
                    policy.right.append(policy_att_name.ptr(), policy_att_name.length());
                }
            }
            else
            {
                if(strncmp((char *)policy_tag.ptr(), "AttValAttval", policy_tag.length()) == 0)
                {
                    policy.left.append("S.");
                    policy.left.append(policy_att_name.ptr(), policy_att_name.length());

                    policy.oper.append(policy_operator.ptr(), policy_operator.length());

                    policy.right.append("O.");
                    policy.right.append(policy_att_name.ptr(), policy_att_name.length());
                }
                else if(strncmp((char *)policy_tag.ptr(), "AttValConstVal", policy_tag.length()) == 0)
                {
                    policy.left.append("S.");
                    policy.left.append(policy_att_name.ptr(), policy_att_name.length());
                    
                    policy.oper.append(policy_operator.ptr(), policy_operator.length());

                    policy.right.append(policy_const_val.ptr(), policy_const_val.length());
                }
                else if(strncmp((char *)policy_tag.ptr(), "EnvValConstVal", policy_tag.length()) == 0)
                {
                    policy.left.append(policy_att_name.ptr(), policy_att_name.length());

                    policy.oper.append(policy_operator.ptr(), policy_operator.length());

                    policy.right.append(policy_const_val.ptr(), policy_const_val.length());
                }
            }
            if(policy.left.length() > 0 && policy.oper.length() >0 &&  policy.right.length() > 0)
            {
                LEX_CSTRING action_t= {(char *)str_action.ptr(), str_action.length()};
                // 表中存的数据
                policy.subject.append(str_subject.ptr(), str_subject.length());
                policy.object.append(str_object.ptr(), str_object.length());
                policy.object_type.append(str_object_type.ptr(), str_object_type.length());

                policy.action = atoi(action_t.str);
                policy.name.append(poli_name.ptr(), poli_name.length());
                policy_map.push_back(policy);
            }
        }
    }
    
    //new added by yuang in 2022.9.26 公共内存解锁
    acl_cache_lock.unlock();
    iterator.reset();
    // table->m_needs_reopen= TRUE;                  // Force close to free memory
    table->invalidate_dict();
    close_trans_system_tables(thd);
    return true;
}



void send_update_fail(THD *thd)
{
    //MEM_ROOT *mem_root= thd->mem_root;
    mem_root_deque<Item *> field_list(thd->mem_root);
    Protocol *protocol = thd->get_protocol();
    field_list.push_back(new Item_empty_string("result", 10));
    if (thd->send_result_metadata(field_list, Protocol::SEND_NUM_ROWS | Protocol::SEND_EOF))
        return;
    protocol->start_row();
    protocol->store_string("update fail", 11, system_charset_info);

    if (protocol->end_row())
        return;
    my_eof(thd);
}

bool update_policy(THD* thd)
{

	if( init_att_map(thd) == false || init_policy_map(thd) == false)
    {
        send_update_fail(thd);
        return true;
    }
    my_ok(thd);
    return false;
}

bool search_policy(string& subject, string& object, int action, vector<PPOLICY>& list)
{
	list.clear();
	for(int i=0; i<policy_map.size();i++)
	{
		if( (policy_map[i].subject==subject || policy_map[i].subject=="any") &&
			(policy_map[i].object==object || policy_map[i].object=="any") &&
			(policy_map[i].action&action || policy_map[i].action==0) )
			list.push_back(&policy_map[i]);
	}
	return false;
}


int get_type_num(ATT_TYPE att_type)
{
    int type_num = 0;
    switch(att_type)
    {
    case ATT_INT:
        type_num = 11;
        break;
    case ATT_DOUBLE:
        type_num = 13;
        break;
    case ATT_STRING:
        type_num = 10;
        break;
    case ATT_SET:
        type_num = 14;
        break;
    }
    return type_num;
}


vector<string> split_string(const string& str, const string& pattern) {
	vector<string> ret;
	if (pattern.empty()) return ret;
	size_t start = 0, index = str.find_first_of(pattern, 0);
	while (index != str.npos) {
		if (start != index)
			ret.push_back(str.substr(start, index - start));
		start = index + 1;
		index = str.find_first_of(pattern, start);
	}
	if (!str.substr(start).empty())
		ret.push_back(str.substr(start));
	return ret;
}

bool match_object(const string& bench_obj, const string& src_obj, const string& src_type)
{
    string type = src_type;
    if(type == "user") 
        return bench_obj == src_obj;

    vector<string> benchs,srcs;
    int bsize=0, osize=0;
    benchs = split_string(bench_obj,".");
    bsize = benchs.size();
    srcs = split_string(src_obj,".");
    osize = srcs.size();

    if(type == "any")
    {
        if(osize == 1) type = "database";
        else if(osize == 2) type = "table";
        else if(osize == 3) type = "column";
        else return false;
    }

    if(type == "database")
    {
        if(bench_obj == "*") return true;
        else return bench_obj == src_obj;
    }
    else if(type == "table")
    {
        if(bsize == 2 && osize ==2 && benchs[0] == srcs[0] && (
            benchs[1] == "*" || benchs[1] == srcs[1]) ) 
        {
            return true;
        }
    }
    else if(type == "column")
    {
        if(bsize == 3 && osize ==3 && benchs[0] == srcs[0] && benchs[1] == srcs[1] && (
            benchs[2] == "*" || benchs[2] == srcs[2]))
        {
            return true;
        }
    }
    return false;
}

//搜索属性，放入list
bool search_att(const string& object,const string& object_type, const string& att_name, VALUE_LIST& list)
{
    int typeNum;
    bool flag=false;
    list.tokens.clear();
	for(int i=0; i<att_map.size();++i)
	{
		if(att_map[i].att_name==att_name &&
            match_object(att_map[i].object, object, object_type))
        {
            list.tokens.push_back(att_map[i].att_value);
            if(!flag)
            {
                list.typeNum = get_type_num( att_map[i].att_type );
                flag = true;
            }
        }
	}
    if(list.tokens.size()>0)
        return true;
	return false;
}


int get_action(THD* thd){   
	int action = 0;
	enum enum_sql_command command = thd->lex->sql_command;
	switch(command)
	{
	case SQLCOM_SELECT:
		action = A_SELECT;
		break;
	case SQLCOM_UPDATE:
		action = A_UPDATE;
		break;
	case SQLCOM_INSERT:
		action = A_INSERT;
		break;
	case SQLCOM_DELETE:
		action = A_DELETE;
		break;
	}
	return action;
}


bool Compare_INT(string& left, TYPE& operate, string& right)
{

    int a = atoi( left.c_str() );   //string to int
    int b = atoi( right.c_str() );

    bool state = false;

    switch(operate.typeNum)
    {
    case 18:
        state = a==b;
        break;
    case 20:
        state = a<b;
        break;
    case 21:
        state = a!=b;
        break;
    case 22:
        state = a<=b;
        break;
    case 23:
        state = a>b;
        break;
    case 24:
        state = a>=b;
        break;
    }
    return state;
}

bool Compare_DOUBLE(string& left, TYPE& operate, string& right)
{
    double a = atof( left.c_str() );
    double b = atof( right.c_str() );

    bool state = false;

    switch(operate.typeNum)
    {
    case 18:
//        state = a==b;
        state = (fabs(a-b)<1e-7);
        break;
    case 20:
        state = a<b;
        break;
    case 21:
//        state = a!=b;
        state = (fabs(a-b)>=1e-7);
        break;
    case 22:
        state = a<=b;
        break;
    case 23:
        state = a>b;
        break;
    case 24:
        state = a>=b;
        break;
    }
    return state;
}





/*支持glob-style的通配符格式,如*表示任意一个或多个字符,?表示任意字符*/  
int stringmatchlen(const char *pattern, int patternLen,  
        const char *str, int stringLen, int nocase)  
{  
    while(patternLen) {  
        switch(pattern[0]) {  
        case '*':  
            while (pattern[1] == '*') {  
                pattern++;  
                patternLen--;  
            }  
            if (patternLen == 1)  
                return 1; /* match */  
            while(stringLen) {  
                if (stringmatchlen(pattern+1, patternLen-1,  
                            str, stringLen, nocase))  
                    return 1; /* match */  
                str++;  
                stringLen--;  
            }  
            return 0; /* no match */  
            break;  
        case '?':  
            if (stringLen == 0)  
                return 0; /* no match */  
            /* 因为？能代表任何字符，所以，匹配的字符再往后挪一个字符 */  
            str++;  
            stringLen--;  
            break;   
        case '\\':  // 转义字符 
            if (patternLen >= 2) {  
                pattern++;  
                patternLen--;  
            }  
            /* fall through */  
        default:  
            /* 如果没有正则表达式的关键字符，则直接比较 */  
            if (!nocase) {  
                if (pattern[0] != str[0])  
                    //不相等，直接不匹配  
                    return 0; /* no match */  
            } else {  
                if (tolower((int)pattern[0]) != tolower((int)str[0]))  
                    return 0; /* no match */  
            }  
            str++;  
            stringLen--;  
            break;  
        }  
        pattern++;  
        patternLen--;  
        if (stringLen == 0) {  
            while(*pattern == '*') {  
                pattern++;  
                patternLen--;  
            }  
            break;  
        }  
    }  
    if (patternLen == 0 && stringLen == 0)  
        //如果匹配字符和模式字符匹配的长度都减少到0了，说明匹配成功了  
        return 1;  
    return 0;  
}  

int stringmatch(const char *pattern, const char *string, int nocase) {
    return stringmatchlen(pattern,strlen(pattern),string,strlen(string),nocase);
}


bool CompareLevel(string left, TYPE& operate, string right)
{
    bool state = false;
    int res; 
    res = levelcmp(left.c_str(), left.length(), right.c_str(), right.length() );
    switch(operate.typeNum)
    {
    case 18:// ==
        state = res==0;
        break;
    case 20://<
        state = res==-1;
        break;
    case 21://!=
        state = res!=0;
        break;
    case 22://<=
        state = res<=0;
        break;
    case 23://>
        state = res==1;
        break;
    case 24://>=
        state = res>=0;
        break;
    }
    return state;
}

bool Compare_STRING(string left, TYPE& operate, string right)
{
    string a = left;
    string b = right;

    bool state = false;
    
    switch(operate.typeNum)
    {
    case 18:
        state = a==b;
        break;
    case 20:
        state = a<b;
        break;
    case 21:
        state = a!=b;
        break;
    case 22:
        state = a<=b;
        break;
    case 23:
        state = a>b;
        break;
    case 24:
        state = a>=b;
        break;
    case 5://like
        state = stringmatch(b.c_str(),a.c_str(),true);
        break;
    }
    return state;
}

bool base_operation(TYPE& left,  VALUE_LIST& list_left, TYPE& operate,
                    TYPE& right, VALUE_LIST& list_right, string att_name)
{
    unsigned long lsize,rsize;
    lsize = list_left.tokens.size();
    rsize = list_right.tokens.size();

    //处理常量，属性-属性不需要进行处理
    if(lsize == 0 && rsize == 0) //常量-常量
    {
        // if(left.typeNum == right.typeNum && (left.typeNum == 29 ||
        //     left.typeNum == 30 || left.typeNum == 31 || left.typeNum == 32)) //环境属性
        if(right.typeNum == 10 && (left.typeNum == 29 ||    //获取的当前环境属性值具有typeNum，而环境属性常量只能解析为字符串
            left.typeNum == 30 || left.typeNum == 31 || left.typeNum == 32)) //环境属性
            {
                list_left.tokens.push_back(left.token);
                list_right.tokens.push_back(right.token);
                list_left.typeNum = list_right.typeNum = left.typeNum; 
            }
        else 
            return false;
    }
    else if(lsize == 0 && rsize > 0)//常量-属性
    {
        //考虑int 和 double相互比较的情况
        if( (left.typeNum == 11 && list_right.typeNum == 13) || 
            (left.typeNum == 13 && list_right.typeNum == 11) )
                left.typeNum = list_left.typeNum = list_right.typeNum = 13;
        if(left.typeNum == list_right.typeNum)
            list_left.tokens.push_back(left.token);
        else
            return false;
    }
    else if(lsize > 0 && rsize == 0 )//属性-常量
    {
        //考虑int 和 double相互比较的情况
        if( (list_left.typeNum == 11 && right.typeNum == 13) || 
            (list_left.typeNum == 13 && right.typeNum == 11) )
                right.typeNum = list_left.typeNum = list_right.typeNum = 13;
        if(right.typeNum == list_left.typeNum)
            list_right.tokens.push_back(right.token);
        else
            return false;
    }

    
    bool result = true;
    for(int i=0;i<list_left.tokens.size();i++)
    {
        for(int j=0;j<list_right.tokens.size();j++)
        {
            switch(list_left.typeNum)
            {
            case 29:
            case 30:
            case 31:
            case 32://环境属性值直接当作字符串进行比较
            case 10:
                if(att_name == "level")
                    result = CompareLevel(list_left.tokens[i], operate, list_right.tokens[j]);
                else
                    result = Compare_STRING(list_left.tokens[i], operate, list_right.tokens[j]);
                break;
            case 11:
                result = Compare_INT(list_left.tokens[i], operate, list_right.tokens[j]);
                break;
            case 13:
                result = Compare_DOUBLE(list_left.tokens[i], operate, list_right.tokens[j]);
                break;
            }
            if(!result) //有任何一个比较结果为失败，就返回false
                return false;
        }
    }
    return true;
}

// 左边的一堆必须都在右边的一堆里面
bool operator_in(vector<string>& list_left,vector<string>& list_right, string att_name)
{
	
	if( att_name == "domain" )
	{
		int res;
		for(int i=0; i<list_left.size(); i++)
		{
		    for(int j=0; j<list_right.size(); j++)
		    {
		        res = domaincmp(list_left[i].c_str(), list_left[i].length(),
				 	list_right[j].c_str(), list_right[j].length());
				  if( res==-1  || res==0)
				      goto next1;
		    }
		    return false;
		    next1:;
		}
		return true;
	}
    else  return false;  //除了domain 其余的不能用 该操做
   
}

//左不在右
bool operator_not_in(vector<string>& list_left,vector<string>& list_right, string att_name)
{
    if( att_name == "domain" )
    {
        int res;
        for(int i=0; i<list_left.size(); ++i)
        {
            for(int j=0; j<list_right.size(); ++j)  // no in 一有相交就直接返回false 
            {
                res = domaincmp(list_left[i].c_str(), list_left[i].length(),
                    list_right[j].c_str(), list_right[j].length());
                if( res==-1  || res==0)
                    return false;
            }
        }
        return true;
    }
    else  return false;  //除了domain 其余的不能用 该操做

}

bool Compare_SET(TYPE& left,
                 VALUE_LIST& list_left,
                 TYPE& operate,
                 TYPE& right,
                 VALUE_LIST& list_right,
                 string att_name)
{
    unsigned long lsize,rsize;
    lsize = list_left.tokens.size();
    rsize = list_right.tokens.size();

    if(lsize == 0 && rsize == 0) // 常量-常量
        return false;
    else if(lsize == 0 && rsize > 0 && left.typeNum == 10)  //常量-属性
        list_left.tokens.push_back(left.token);
    else if(lsize > 0 && rsize == 0 && right.typeNum == 10) //属性-常量
        list_right.tokens.push_back(right.token);
    // 排除两个都是范畴的情况后，剩余情况为：如果一边是范畴 另一边不是范畴 也不是字符串常量 就是不可比的
    else if( !(lsize > 0 && rsize > 0) ) 
        return false; 

    bool result = false;
    switch(operate.typeNum)
    {
    case 1:
        result = operator_in(list_left.tokens, list_right.tokens, att_name);
        break;
    case 2:
        result = operator_not_in(list_left.tokens, list_right.tokens,att_name);
        break;
    }
    return result;
}

/**
 * @brief 给定主体+主体属性、客体+客体属性、运算符，判断逻辑表达式（主体.属性 操作符 客体.属性）是否成立，操作符一侧可以是常量
 * subject,object是具体当前状态下的主客体，
 *       例：主体为用户sub="username@host"，客体为数据库obj="mysql.*"
 * left,operate,right均为解析出来的字符串，
 *       left,right可能为：  1.主体属性（"S.domain"）或者客体属性（"O.domain"）
 *                          2. 环境属性（"date"）
 *                          3. 常量
 */
bool Compare(string subject, string object, string object_type, TYPE left, TYPE operate, TYPE right)
{
    VALUE_LIST list_left, list_right;
    list_left.typeNum = list_right.typeNum = -1;
    string att_name;
    
    //先考虑客体
    if( left.typeNum == 7 )
    {
        att_name = left.token;
		//将指定实体的对应属性放入list_left ,left.token即为属性名称
        if(!search_att(object, object_type, left.token, list_left))   //客体没有属性，算通过
            return true;    
    }
    else if( right.typeNum == 7 )
    {
        att_name = right.token;
        if(!search_att(object, object_type, right.token, list_right))
            return true;
    }

    //考虑主体
    if( left.typeNum == 6 ) 
    {
        att_name = left.token;
        if(!search_att(subject, "user", left.token, list_left))   //主体没有属性 算不过
            return false;
    }
    else if( right.typeNum == 6 )
    {
        att_name = right.token;
    	if(!search_att(subject, "user", right.token, list_right))
            return false;
    }
    
    
    //以左为例，list_left存匹配到的属性项，left存可能的常量
    bool result = false;
    switch(operate.typeNum)
    {
    case 1:
    case 2:
        result = Compare_SET(left, list_left, operate, right, list_right, att_name);
        break;
    case 5:   //like
    case 18: //==
    case 20: //<
    case 21: //!= 
    case 22: //<=
    case 23: //>
    case 24: //>=
        result = base_operation(left, list_left, operate, right, list_right, att_name);
        break;
    }
    return result;
}

int policy_decision(string subject,string object, PPOLICY policy,string s_ip)
{
    SyntaxParseAnalysis decision(policy->left, policy->oper,policy->right ,s_ip);
    decision.sub = subject;
    decision.obj = object;
    decision.obj_type = policy->object_type;    //todo：考虑这个type具体应该怎么用
    if( decision.analysis() > 0 )   return 1;
    else    return 0; 
}



bool search_conf_policy(string& subject, string& object, int action, vector<PPOLICY>& list)
{
	list.clear();
	for(int i=0; i<policy_map.size();i++)
	{
		if( (policy_map[i].subject==subject || policy_map[i].subject=="any") &&
			(policy_map[i].object==object || policy_map[i].object=="any") &&
			(policy_map[i].action&action || policy_map[i].action==0) )
			list.push_back(&policy_map[i]);
	}
	return false;
}