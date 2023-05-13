#pragma once
#include <string>
#include <vector>
using std::vector;
using std::string;

struct Tuple
{
	int typeNum;    
	string token;   
};

typedef struct Tuple TYPE;
bool Compare(string subject, string object, string object_type, TYPE left, TYPE operate, TYPE right); 


class SyntaxParseAnalysis
{
private:
	string left;
	string oper;
	string right;
	
	vector<TYPE> Item;
	vector<TYPE> Operate;
    string s_ip;

public:
    string add_ip_zero(string str);  //ip补全 
	SyntaxParseAnalysis(string lf,string op,string rig,string ip);
	bool isNUM(string str);
	bool isDouble(string str);
	bool isIP(string str);
	TYPE lex(string str);
	int  analysis(); 
	string sub;
	string obj;
	string obj_type;

};


