#include "SyntaxParseAnalysis.h"
#include<ctime>
#include<string>

string SyntaxParseAnalysis::add_ip_zero(string str)  //设定 所有IP地址均为 x.x.x.x  的形式
{
	string ret = "";
	if(str == "localhost" || str == "127.0.0.1")  return ret = "localhost";
	else 
	{
		int before = 0;
		for(int i = 0 ;i < str.length();++i)
		{
			if(str[i] == '.')
			{
			   string temp = str.substr(before,i-before);
			   if(temp.length() == 1 )  temp  = "00"+temp;
               else if(temp.length() == 2) temp  = "0"+temp;
               ret+= temp;
			   ret+=".";
			   before = i+1;
			}
		}
        string temp_s  = str.substr(before,str.length() - before); 
		if(temp_s.length() == 1 )  temp_s  = "00"+temp_s;
        else if(temp_s.length() == 2) temp_s  = "0"+temp_s;
		ret += temp_s;
	}
	return ret;
}

SyntaxParseAnalysis::SyntaxParseAnalysis(string lf,string op,string rig,string ip)
{
	left = lf;
	oper = op;
	right = rig;
	s_ip = add_ip_zero(ip);
}

bool SyntaxParseAnalysis::isNUM(string str)
{
	for (int i = 0; i < str.length(); i++)
	{
		if (str[i]<'0' || str[i]>'9') return false;
	}
	return true;
}
bool SyntaxParseAnalysis::isDouble(string str)
{
    int cnt_dot = 0;
    if(atof(str.c_str()) == 0.0)
    {
        for(int i = 0 ; i < str.length();++i) 
        {
            if(str[i] == '0') continue;
            else if (str[i] == '.' )  ++cnt_dot;  
            else return false;
        }
    }
    return cnt_dot <=1 ;
}



bool SyntaxParseAnalysis::isIP(string str)   // 用来判断策略文本中的子字符串是否为ip
{
	if(str[0] == '\'' && str[str.length() - 1] == '\'')
	{
		str = str.substr(1,str.length()-2);
	}
	int cnt = 0;
	for (int i = 0; i < str.length(); i++)
	{
		if (str[i]== '.') ++cnt;
	}
	if (cnt == 3)
	{
        return true;
	} 
	else
	{ 
        return false;
	}
}


TYPE SyntaxParseAnalysis::lex(string str)
{
	TYPE ret;
	char x[3] = { 0 }, y[255] = { 0 };
	if (str.length() >= 3)
	{
		str.copy(x, 2, 0);
		str.copy(y, str.length() - 2, 2);
	}

	ret.token = str;
	if (str == "") ret.typeNum = -1;
	else if (str == "in" || str=="IN") ret.typeNum = 1;
	else if (str == "notin"||str=="NOTIN") ret.typeNum = 2;
	else if (str == "like" || str == "LIKE") ret.typeNum = 5;
	else if (string(x) == "S." || string(x) == "s.")
	{
		ret.token = string(y);
		ret.typeNum = 6;
	}
	else if (string(x) == "O." || string(x) == "o.")
	{
		ret.token = string(y);
		ret.typeNum = 7;
	}
	else if (str == "time")//time_now
	{
		ret.typeNum = 29;
	}
	else if (str == "date")//date_now
	{
		ret.typeNum = 30;
	}
	else if (str == "weekday") //weekday_now
	{
		ret.typeNum = 31;
	}
	else if (str == "ip")  //my_ip
	{
	 	ret.typeNum = 32;
	}
	else if (isIP(str))  {  ret.typeNum = 10;  str = str.substr(1,str.length()-2);  ret.token = add_ip_zero(str); }
	else if (str[0] == '\'' && str[str.length() - 1] == '\'')
	{
		str.copy(y, str.length() - 2, 1);   //ok 
		ret.token = string(y);
		ret.typeNum = 10;
	}
	else if (isNUM(str)) ret.typeNum = 11;
	else if (isDouble(str)) ret.typeNum = 13;
	else if (str == "==") ret.typeNum = 18;
	else if (str == "<") ret.typeNum = 20;
	else if (str == "!=") ret.typeNum = 21;
	else if (str == "<=") ret.typeNum = 22;
	else if (str == ">") ret.typeNum = 23;
	else if (str == ">=") ret.typeNum = 24;
	else if (str == "#") ret.typeNum = 0;
	else  ret.typeNum = -1;
	return ret;
}

string my_toString(int n)   // int 转string
{   
   string ret = "";
   if(n == 0) return ret = "00"; 
   else if( n >=1 && n <=9 )  // 说明是一位数
   {
      ret = "00";
	  ret[1] = '0'+n;
	  return ret;
   }
   else   // 说明是两位数
   {
	int m = n;
    char s[100];
    char ss[100];
    int i=0,j=0;
    while (m>0)
    {
        s[i++] = m % 10 + '0';
        m /= 10;
    }
    s[i] = '\0';
    i = i - 1;
    while (i >= 0)
    {
        ss[j++] = s[i--];
    }
    ss[j] = '\0';
    return ss;
   }
}

int SyntaxParseAnalysis::analysis()
{
	//0--false 1--true -1---Syntax Error
	TYPE currentstr;
	vector<string> vecs;
	vecs.push_back(left);
	vecs.push_back(oper);
	vecs.push_back(right);
	vecs.push_back("#");

	for(int i = 0 ;i < vecs.size();++i) 
	{
		string tmp = vecs[i];
		currentstr = lex(tmp);
		switch (currentstr.typeNum)
		{
		case -1:
			return -1;
			break;
		case 6:
		case 7:
		case 8:
		case 10:
		case 11:
		case 13:
			Item.push_back(currentstr);
			break;
		case 29:  // time  hh:mm:ss 作为string对比
		{
			TYPE ret;
			time_t now = time(0);
			tm *gmtm = localtime(&now);
            string hour= my_toString(gmtm->tm_hour);
            if(hour.length() ==1) hour = "0"+hour;
            string min = my_toString(gmtm->tm_min);
            if(min.length() ==1) min = "0"+min;
            string sec = my_toString(gmtm->tm_sec);
            if(sec.length() ==1) sec = "0"+sec;
			ret.token = hour + ":" + min + ":" + sec;
			ret.typeNum = 29;	//后续会用到，如果是环境变量，那么在比较时为常量-常量模式
			Item.push_back(ret);
			break;
		}
		case 30:  //date   yyyy-mm-dd 作为string对比
		{
			TYPE ret;
			time_t now = time(0);
			tm *gmtm = localtime(&now);
            string year= my_toString(gmtm->tm_year+1900);
            string mon = my_toString(gmtm->tm_mon+1);
            if(mon.length() ==1) mon = "0"+mon;
            string mday = my_toString(gmtm->tm_mday);
            if(mday.length() ==1) mday = "0"+mday;
			ret.token = year + "-" + mon + "-" + mday;
			ret.typeNum = 30;
			Item.push_back(ret);
			break;
		}
		case 31:  //weekday  1-7 作为string对比
		{
			TYPE ret;
			time_t now = time(0);
			tm *gmtm = localtime(&now);
            string wday = my_toString(gmtm->tm_wday);
            if(wday == "00") wday = "7";
			else 
			{
				// 去掉星期几的前导0
				if(wday.length() == 2)
				{
					wday = wday.substr(1,1);
				}
			}
			ret.token = wday;
			ret.typeNum = 31;
			Item.push_back(ret);
			break;
		}
		 case 32:  // ip  作为string对比
		 {
		 	TYPE ret;
		 	ret.token = s_ip;          // 从系统中提取的 补0后的IP地址
		 	ret.typeNum = 32;
		 	Item.push_back(ret);
		 	break;
		 }

		case 0: // 0是#号  说明到末尾了
			while (Operate.size() > 0) 
			{
				if (Item.size() < 2 || Operate.back().typeNum == 27) return -1;
				TYPE item1, item2, opert, ret;
				item2 = Item.back();
				Item.pop_back();
				item1 = Item.back();
				Item.pop_back();
				opert = Operate.back();
				Operate.pop_back();
				if (Compare(this->sub,this->obj, this->obj_type, item1, opert, item2))
				{
					ret.token = "1";
					ret.typeNum = 11;
				}
				else
				{
					ret.token = "0";
					ret.typeNum = 11;
				}
				Item.push_back(ret);
			}
			if(Item.size() == 0) return 0;
			if (Item.back().token == "0") return 0;
			else if (Item.back().token == "1") return 1;
			else return -1;
			break;

		case 1:
		case 2:
		case 5:
		case 18:
		case 20:
		case 21:
		case 22:
		case 23:
		case 24:
			if (Operate.size() > 0 && 
			    Operate.back().typeNum != 3 && 
				Operate.back().typeNum != 4 && 
				Operate.back().typeNum!=27) return -1;
			Operate.push_back(currentstr);
			break;

		default:
			break;
		}
	}

	if (Item.back().token == "0") return 0;
	else if (Item.back().token == "1") return 1;
	else return -1;
}
