#include <iostream>
//#include<fstream>
#include <string>

using namespace std;

void defineFilterPolicy(string StoreLog[21][10]);
void generatingLogs(string USER,string days,string times,bool idle,bool block,bool ALLPORT,bool Ax,bool moretimes,bool Ar,bool Aw,bool Ra,bool Au,bool ALLDAY,bool FindUser,bool Aux,string StoreLog[21][10],int day,bool idledisplay, int rowinaday,bool actionsmorethan,int action, bool Specificport, int specificport, bool USEREXCEPT,bool jumpport, int portfrom, int portend, bool specificday,bool jumpday,int dayfrom,int dayend, int totalpolicy, bool blocksametime,int sametimeblock, bool boolcontinuous, int continuoustimes,bool rules3 ,int rules3time ,bool defaultsbool ,bool jumpspecificport , int PORTS[21],int totalport,bool jumpspecificday,int totalday,int numberofday,int daysrecordjump[10]);
void checkRa(string temprecord, bool Ar,bool Aw,bool Ax, bool actionsmorethan,int action,int totalpolicy,string FINDSPECIFICUSERATALLDIFFERENTPORT[30][10], bool boolcontinuous, int continuoustimes,bool blocksametime,int sametimeblock,bool defaults,int counterport,int counterday);
void checkAu(string temprecord, bool Ar,bool Aw,bool Ax, bool actionsmorethan,int action,int totalpolicy,string FINDSPECIFICUSERATALLDIFFERENTPORT[30][10], bool boolcontinuous, int continuoustimes,bool blocksametime,int sametimeblock,bool defaults,int counterport,int counterday);
void recordExceptAnonymous(string temprecord, bool Ar,bool Aw,bool Ax, bool actionsmorethan,int action,string USER,int totalpolicy,string FINDSPECIFICUSERATALLDIFFERENTPORT[30][10],bool boolcontinuous, int continuoustimes,bool blocksametime,int sametimeblock,bool defaults,int counterport,int counterday);
void CheckUser(string temprecord,bool Ar,bool Aw,bool Ax,string USER,bool idledisplay,int rowinaday,bool actionsmorethan,int action,int totalpolicy,string FINDSPECIFICUSERATALLDIFFERENTPORT[30][10], bool boolcontinuous, int continuoustimes,bool blocksametime,int sametimeblock,bool defaults,int totalport, bool jumpspecificport, int PORTS[21] ,int counterport,int counterday);
void readFiltering();
void blockinarowcontinue(string finalstring,   bool boolcontinuoustimes, int times,bool Aw, bool Ax, bool Ar ,int counterport,int counterday,int totalpolicy);
void RecordSameTimeSamePort(string FINDSPECIFICUSERATALLDIFFERENTPORT[30][10],string USER, int sametimeblock,string action,int totalpolicy,bool jumpspecificday, int totalday,int daysrecordjump[10]);
void RolesOf_TheDay(string StoreLog[21][10],string USER, int sametimeblock,string action,int totalpolicy,bool jumpspecificday, int totalday,int daysrecordjump[10],int totalport,int PORTS[21],bool jumpspecificport , bool jumpday , int dayfrom , int dayend , bool jumpport , int portfrom , int portend);
void SPECIFIC_User_Continue(string finalstring,   bool boolcontinuoustimes, int times,bool Aw, bool Ax, bool Ar ,int counterport,int counterday,int totalpolicy,string USER);
void SPECIFIC_EXCEPT_User_Continue(string finalstring,   bool boolcontinuoustimes, int times,bool Aw, bool Ax, bool Ar ,int counterport,int counterday,int totalpolicy,string USER);

