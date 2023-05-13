#ifndef POLICY_H
#define POLICY_H

//  #include "my_global.h"
#include "lex_string.h"
#include "m_string.h"

#include <string>
using std::string;
#include <vector>
using std::vector;

#define A_SELECT	0x00000001
#define A_UPDATE	0x00000002
#define A_INSERT	0x00000004
#define A_DELETE	0x00000008
#define A_LOGIN		0X00000010


typedef enum __ATT_TYPE{ATT_NONE, ATT_INT, ATT_DOUBLE, ATT_STRING,  ATT_SET} ATT_TYPE;

typedef struct __ATT
{
	string object;
	string att_name;
	ATT_TYPE att_type;
	string att_value;
}ATT, *PATT;

typedef struct __POLICY
{
	string subject;
	string object;
	string object_type;
	int action;
	
	string left;
	string oper;
	string right;

	string name;
}POLICY, *PPOLICY;

typedef struct _ATTS
{
      LEX_CSTRING id_t;
      LEX_CSTRING name_t;
      LEX_CSTRING type_t;
}ATTS;

typedef struct _VALUE_LIST
{
	int typeNum;
	vector<string> tokens;
}VALUE_LIST, *PVALUE_LIST;


class THD;
struct TABLE;

ATT_TYPE get_att_type(LEX_CSTRING& type);
void get_att( vector<ATTS> ALL_ATTS ,LEX_CSTRING& id, ATT& att);
bool init_att_map(THD* thd);
bool init_policy_map(THD* thd);
bool update_policy(THD* thd);
bool search_policy(string& subject, string& object, int action, vector<PPOLICY>& list);
bool search_conf_policy(string& subject, string& object, int action, vector<PPOLICY>& list);

/**
 * @brief 将涉及到的对象的属性都拿出来，放入list
 */
bool search_att(const string& object,const string& object_type, const string& att_name, VALUE_LIST& list);
int get_action(THD* thd);
int policy_decision(string subject,string object, PPOLICY policy,string s_ip);

#endif	//POLICY_H
