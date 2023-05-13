#ifndef SQL_SIGN_MANAGE_H
#define SQL_SIGN_MANAGE_H

#include "lex_string.h"  //  LEX_STRING
#include "m_string.h"

#include "policy.h"
#include "sec_sign.h"
#include <vector>
using std::vector;
#include <string>
using std::string;
#include <queue>
using std::queue;
#include <map>
using std::map;

struct sign
{
    string level;
    vector<string> domain;
};
typedef struct sign SIGN;

class THD;
struct TABLE;

unsigned int getLength(char *str);
char *getToken(char *str, int num);
int getCount(char *str);
bool compare(char *str1, char *str2, int num);
void toLower(char *command);
bool sqlParsing(THD *thd,COM_DATA com_data);
void reset_statement(THD *thd);

bool mysql_add_domain_relation(THD *thd,vector<LEX_STRING>& paramaters);
bool mysql_add_level_realtion(THD *thd,vector<LEX_STRING>& paramaters);
bool mysql_delete_domain_relation(THD *thd,vector<LEX_STRING>& paramaters);
bool mysql_delete_level_relation(THD *thd,vector<LEX_STRING>& paramaters);
void send_access_deny(THD* thd);
bool mysql_show_level(THD *thd,vector<LEX_STRING>& paramaters);
bool mysql_show_domain(THD *thd,vector<LEX_STRING>& paramaters);
bool init_domain(THD* thd, vector<BRIM> &list);
bool init_level(THD* thd, vector<BRIM> &list);
void init_level(vector<BRIM> &list);
void init_domain(vector<BRIM> &list);
bool init_sign(THD* thd);
bool show_all_domain(THD* thd);
bool show_all_level(THD * thd);
bool show_all_domain_relation(THD* thd);
bool show_all_level_relation(THD* thd);
bool show_all_sign(THD* thd);
bool save_sign(THD* thd);


bool grant_domain_to_obj(THD *thd,vector<LEX_STRING>& paramaters);
bool grant_level_to_obj(THD *thd,vector<LEX_STRING>& paramaters);

bool alter_policy_enable(THD *thd,vector<LEX_STRING>& paramaters);
bool alter_policy_disable(THD *thd,vector<LEX_STRING>& paramaters);

// 单独增加一条 level_sec  domain_sec
bool mysql_add_domain_sec(THD *thd,vector<LEX_STRING>& paramaters);
bool mysql_add_level_sec(THD *thd,vector<LEX_STRING>& paramaters);

// 单独删掉一条 domain_sec  level_sec
bool mysql_delete_level_sec(THD *thd,vector<LEX_STRING>& paramaters);
bool mysql_delete_domain_sec(THD *thd,vector<LEX_STRING>& paramaters);

int  close_abac(THD* thd);

/**add by yuang in 20221005  start */
bool mysql_add_policy(THD *thd,vector<LEX_STRING>& paramaters);
bool mysql_delete_policy(THD *thd,vector<LEX_STRING>& paramaters);
bool show_all_policy(THD *thd);
bool mysql_add_attribute(THD *thd,vector<LEX_STRING>& paramaters);
bool mysql_delete_attribute(THD *thd,vector<LEX_STRING>& paramaters);
bool show_all_attributes(THD *thd);
bool mysql_add_attribute_manager(THD *thd,vector<LEX_STRING>& paramaters);
bool mysql_delete_attribute_manager(THD *thd,vector<LEX_STRING>& paramaters);
bool show_all_attributes_manager(THD *thd);

/**add by yuang in 20221005  end */





bool check_abac_access(THD *thd, List<LEX_USER> &list);
bool check_abac_access_alter(THD *thd, List<LEX_USER> &list);
bool check_sign(THD* thd, LEX_CSTRING db);
bool check_sign(THD* thd, LEX_CSTRING db, LEX_CSTRING table);
bool check_sign(THD* thd, LEX_CSTRING db, LEX_CSTRING table, LEX_CSTRING col_name);

#endif //SQL_SIGN_MANAGE_H
