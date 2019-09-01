#include <iostream>
#include <fstream>
#include <map>
#include <sstream>
#include <windows.h>
#include <cstring>
#include <string>
#include "functionprototype.h"

using namespace std;

int const integer = 100;
string LOGDATA[integer+1];
string SPECIFICKEYWORDSGRAMMER[25];

int main()
{
    ifstream read("logpattern.txt");
    int counter = 0;
    if(!read.is_open())
    {
        cout<<"Logpattern.txt is missing "<<endl;
        cout<<"This will lead your log files format ruin your records "<<endl;
        return 0;
    }
    while(!read.eof())
    {
        string data;
        getline(read,data);
        LOGDATA[counter]=data;
        counter ++;
    }


    ifstream readdynamic("dynamicgrammer.txt");
    counter = 0;
    if(!readdynamic.is_open())
    {
        cout<<"dynamicgrammer.txt is missing "<<endl;
        cout<<"This will lead your filter policy not able to detect the keywords "<<endl;
        return 0;
    }
    while(!readdynamic.eof())
    {
        string data;
        getline(readdynamic,data);
        SPECIFICKEYWORDSGRAMMER[counter]=data;
        counter ++;
    }

    ifstream readPort[21];
    string StoreLog[21][10];
    string portFile = "ports\\port40";
    string rawLog;
    for(int i =0 ; i<=20 ; i++)
    {
        string portFile = "ports\\port40";
        if(i < 10)
        {
            portFile.insert(portFile.length(),"0");
        }
        portFile= portFile+to_string(i)+".txt";
        readPort[i].open(portFile.c_str());
        int counter = 0;
        while(!readPort[i].eof())
        {
            getline(readPort[i],rawLog);
            if(rawLog.compare("")!=0)
            {
                StoreLog[i][counter]=rawLog;
            }
            if(counter != 10)
            {
            }
            counter = counter +1 ;
        }
        readPort[i].close();
    }
    defineFilterPolicy(StoreLog);
    //readFiltering();
    return 0;
}

void defineFilterPolicy(string StoreLog[21][10] )
{
    int TotalPolicyRules=1;
top:
    ifstream readFilterPolicy("filterpolicy.txt");
    if(!readFilterPolicy.good())
    {
        system("echo -idle -Ax -Aw -Ar>filterpolicy.txt");
        goto top ;
    }
    while(!readFilterPolicy.eof())
    {
        string USER,policy,port,times,days="99";
        int specificport, day, rowinaday,pointer=0;
        bool idle = false,block = false, ALLPORT = true, Ax=false, moretimes=false, Ar=false, Aw=false,  idledisplay = false, Ra=false,jumpport= true,ALLDAY= true, actionsmorethan=false,  Au = true,FindUser = false,  Aux = false, Specificport = false,USEREXCEPT = false;
        bool specificday=false, jumpday=false,blocksametime = false, comment = false, boolcontinuous = false, rules3 =false,defaults=true,jumpspecificport=false, jumpspecificday = false;
        int dayfrom, dayend,continuoustimes,portfrom,portend;

        getline(readFilterPolicy,policy);
        if (policy[0]=='#' && policy[1]!='#' && policy[2]!='#' || policy[0]=='#' && policy[1]=='#' && policy[2]=='#')
        {
            comment=true;
        }
        if(policy[0] == '#' && policy[1]=='#' && policy[2]!='#')
        {
            for(int i = 2; i <policy.length() ; i++ )
            {
                if(policy[i]=='#' && policy[i+1]=='#')
                {
                    cout<<"Comments message \""<<policy.substr(2,i-2)<<"\""<<endl;
                    policy=policy.substr(i+2,policy.length());
                    cout<<"ALERT STRING AFTER EDIT"<<policy<<endl;
                    cout<<"My new policy line is "<<policy<<endl;
                    break;
                }
            }
        }
        if(policy == "")
        {
            continue;
        }

        if(comment == true)
        {
            cout<<"Rules "<<TotalPolicyRules <<" SKIPPED "<<endl;
            TotalPolicyRules = TotalPolicyRules +  1;
            continue;
        }
        cout<<"\n-------------------------------------------------------------\n\n";
        cout<<TotalPolicyRules<<" Policy Line \n"<<endl;
        cout<<"Checklists :"<<endl;
        //find port needed or not
        int totalport=0;
        int numberofport=0;
        int PORTS[21];
        //find port needed or not
        std::size_t found =policy.find(SPECIFICKEYWORDSGRAMMER[0],pointer);
        if (found!=std::string::npos)
        {
            Specificport = true;
            ALLPORT=false;
            string test;
            jumpport = false;
            int length = SPECIFICKEYWORDSGRAMMER[0].length();
            int counter=0;
            for( int i = found+length ; i < policy.length()+1 ; i++)
            {
                if(policy[i]==32 || policy[i]==0)
                {
                    totalport++;
                    PORTS[counter]=stoi(test);
                    counter++;
                    break;
                }
                else if(policy[i]==44)
                {
                    totalport++;
                    PORTS[counter]=stoi(test);
                    counter++;
                    test="";
                }
                else
                {
                    test = test + policy[i];
                }
            }

            if(totalport > 1)
            {
                if(jumpspecificport ==false)
                {
                    cout<<"Record port ";
                }
                jumpspecificport=true;
            }
            for(int i = 0 ; i<totalport ; i++ )
            {
                cout<<PORTS[i]<<" ";
            }
            cout<<endl;
            specificport = PORTS[0];
            specificport = specificport - 4000;
        }
        pointer = 0;    //find idle needed or not in the policy.txt
        found =policy.find(SPECIFICKEYWORDSGRAMMER[1],pointer);
        if (found!=std::string::npos)
        {
            idle=true;
            actionsmorethan = false;
            idledisplay = false;
            cout<<"Idle "<<endl;
        }
        pointer = 0;    //Record any execution
        found =policy.find(SPECIFICKEYWORDSGRAMMER[2],pointer);
        if (found!=std::string::npos)
        {
            Ax=true;
            cout<<"Execution is require"<<endl;
        }
        pointer = 0;    //Record any read
        found =policy.find(SPECIFICKEYWORDSGRAMMER[3],pointer);
        if (found!=std::string::npos)
        {
            Ar=true;
            cout<<"Read is require "<<endl;
        }
        pointer = 0;    //Record any write
        found =policy.find(SPECIFICKEYWORDSGRAMMER[4],pointer);
        if (found!=std::string::npos)
        {
            Aw=true;
            cout<<"Write is require"<<endl;
        }
        pointer = 0;    //Record anonymous only
        found =policy.find(SPECIFICKEYWORDSGRAMMER[5],pointer);
        if (found!=std::string::npos)
        {
            Ra=true;
            FindUser = false;
            Aux= false;
            Au = false;
            cout<<"Anonymous actions is require "<<endl;
        }
        pointer = 0;    //find all idle connections
        found =policy.find(SPECIFICKEYWORDSGRAMMER[6],pointer);
        if (found!=std::string::npos)
        {
            Aux =false;
            FindUser=false;
            idle = false;
            Au =false;
            actionsmorethan = false;
            idledisplay = true;
            defaults=false;
            times = policy.substr(found+SPECIFICKEYWORDSGRAMMER[6].length(),2);
            rowinaday=stoi(times);
            cout<<"Find inactive equal or more than"<<times<<endl;
        }
        pointer = 0;
        string temp;
        found =policy.find(SPECIFICKEYWORDSGRAMMER[7],pointer);             //jump port
        if (found!=std::string::npos)
        {
            ALLPORT =false;
            Specificport = false;
            jumpport = true;
            temp = policy.substr(found+SPECIFICKEYWORDSGRAMMER[7].length(),4);
            cout<<"Records on from port "<<temp<<" until ";
            portfrom =stoi(temp);
            portfrom = portfrom - 4000;
            temp = policy.substr(found+SPECIFICKEYWORDSGRAMMER[7].length()+5,4);
            cout<<"port "<<temp<<" is require"<<endl;
            portend =stoi(temp);
            portend = portend - 4000;

        }
        pointer = 0;
        found =policy.find(SPECIFICKEYWORDSGRAMMER[8],pointer);             //jump day
        if (found!=std::string::npos)
        {
            ALLDAY =false;
            specificday = false;
            jumpday = true;
            temp = policy.substr(found+SPECIFICKEYWORDSGRAMMER[8].length(),2);
            cout<<"Records on from day "<<temp<<" until ";
            dayfrom =stoi(temp);
            dayfrom = dayfrom;
            temp = policy.substr(found+SPECIFICKEYWORDSGRAMMER[8].length()+3,2);
            cout<<"day "<<temp<<" is require"<<endl;
            dayend =stoi(temp);
            dayend = dayend+1;
        }
        int totalday=0;
        int numberofday=0;
        int daysrecordjump[10];
        pointer = 0;
        found = policy.find(SPECIFICKEYWORDSGRAMMER[9],pointer);             //record specific day
        if (found!=std::string::npos)
        {
            specificday = true;
            ALLDAY = false;
            jumpday =false;
            string test="";
            days= policy.substr(found+SPECIFICKEYWORDSGRAMMER[9].length(),1);
            for( int i = found+SPECIFICKEYWORDSGRAMMER[9].length() ; i <=policy.length() ; i++)
            {
                if(policy[i]==32 || policy[i]==0)
                {
                    daysrecordjump[totalday]=stoi(test);
                    totalday++;
                    break;
                }
                else if(policy[i]==44)
                {
                    daysrecordjump[totalday]=stoi(test);
                    test="";
                    totalday++;
                    continue;
                }
                else
                {
                    test=test+policy[i];
                }
            }
            cout<<"days of totalday"<<totalday<<endl;
            if(totalday > 1)
            {
                if(jumpspecificday ==false)
                {
                    cout<<"Record port ";
                }
                jumpspecificday =true;
            }
            int counter=0;
            cout<<" Days ";
            for(int i = 0 ; i<totalday ; i++)
            {
                cout<<daysrecordjump[i]<<"  ";
            }
            cout<<endl;
            day=stoi(days);
        }
        pointer=0;
        found =policy.find(SPECIFICKEYWORDSGRAMMER[10],pointer);   // Record ALL USER EXCEPT ANONYMOUS
        if (found!=std::string::npos)
        {
            Aux = true;
            Au = false;
            Ra = false;
            USEREXCEPT=false;
            FindUser = false;
            cout<<"Record specific records ->ALL except Anonymous "<<endl;
        }
        pointer = 0;
        found =policy.find(SPECIFICKEYWORDSGRAMMER[11],pointer);   // Record ALL USER EXCEPT ANONYMOUS
        if (found!=std::string::npos)
        {
            USEREXCEPT = true;
            Aux = false;
            Au = false;
            Ra = false;
            FindUser = false;
            for(int i=found+SPECIFICKEYWORDSGRAMMER[11].length(); i<policy.length(); i++)
            {
                if(policy[i]==32 || policy[i]==0)
                {
                    break;
                }
                else if( policy[i]==44 || policy[i]==124 || policy[i]==46)
                {
                    continue;
                }
                else
                {
                    USER=USER+policy[i];
                }
            }
            cout<<"Record specific records ->ALL except user "<<USER<<endl;
        }
        int action;
        pointer = 0;
        found =policy.find(SPECIFICKEYWORDSGRAMMER[12],pointer);   // find action(r/x/w) more than
        if (found!=std::string::npos && Aux == false)
        {
            idledisplay = false;
            defaults=false;
            actionsmorethan = true;
            times = policy.substr(found+SPECIFICKEYWORDSGRAMMER[12].length(),2);
            action=stoi(times);
            cout<<"BASELINE Total actions is "<<action<<endl;

        }
        pointer = 0;
        found =policy.find(SPECIFICKEYWORDSGRAMMER[13],pointer);   // find SPECIFIC USERS
        if (found!=std::string::npos  )
        {
            FindUser = true;
            USEREXCEPT = false;
            Aux = false;
            Ra = false;
            Au = false;
            idle=false;
            idledisplay=false;
            for(int i=found + SPECIFICKEYWORDSGRAMMER[13].length(); i<policy.length(); i++)
            {
                if(policy[i]==32 || policy[i]==0)
                {
                    break;
                }
                else if( policy[i]==44 || policy[i]==124 || policy[i]==46)
                {
                    continue;
                }
                else
                {
                    USER=USER+policy[i];
                }
            }
            cout<<"Find this specific user records -> "<<USER<<endl;
        }
        int sametimeblock;
        pointer = 0;
        found =policy.find(SPECIFICKEYWORDSGRAMMER[14],pointer);   // RECORD ALL DAYS AND ALL PORTS TO CHECK THE SAME USER AND ACTIONS
        if (found!=std::string::npos  )
        {
            blocksametime=true;
            boolcontinuous=false;
            defaults=false;
            rules3=false;
            actionsmorethan=false;
            string block;
            block= policy.substr(found+SPECIFICKEYWORDSGRAMMER[14].length(),2);
            sametimeblock=stoi(block);
            cout<<"Record this same time and day at the different port "<<sametimeblock<<endl;
        }

        pointer = 0;
        found =policy.find(SPECIFICKEYWORDSGRAMMER[15],pointer);   // RECORD ALL BLOCK ALL THE SAME TIME
        if (found!=std::string::npos  )
        {
            boolcontinuous=true;
            blocksametime=false;
            rules3=false;
            defaults=false;
            actionsmorethan=false;
            string temp5;
            temp5= policy.substr(found+SPECIFICKEYWORDSGRAMMER[15].length(),2);
            continuoustimes=stoi(temp5);
            cout<<"Continuously "<<continuoustimes<<endl;
        }
        int rules3time;
        pointer = 0;
        found =policy.find(SPECIFICKEYWORDSGRAMMER[16],pointer);   // RECORD ALL BLOCK ALL THE SAME TIME
        if (found!=std::string::npos  )
        {
            rules3=true;
            boolcontinuous=false;
            blocksametime=false;
            defaults=false;
            actionsmorethan=false;
            string temp5;
            temp5= policy.substr(found+SPECIFICKEYWORDSGRAMMER[16].length(),2);
            rules3time=stoi(temp5);
            cout<<"Continuously "<<rules3time<<endl;
        }

        generatingLogs( USER,  days, times, idle, block, ALLPORT, Ax,moretimes, Ar, Aw, Ra, Au, ALLDAY, FindUser, Aux,StoreLog,day,idledisplay, rowinaday, actionsmorethan,action, Specificport, specificport,USEREXCEPT, jumpport,  portfrom,  portend,specificday, jumpday, dayfrom, dayend, TotalPolicyRules, blocksametime,sametimeblock,  boolcontinuous,  continuoustimes,rules3, rules3time,defaults, jumpspecificport, PORTS,totalport,jumpspecificday,totalday,numberofday,daysrecordjump);
        TotalPolicyRules = TotalPolicyRules +  1;
    }
}

//navigating to policy
void generatingLogs(string USER, string days,string times,bool idle,bool block,bool ALLPORT,bool Ax,
                    bool moretimes,bool Ar,bool Aw,bool Ra,bool Au,bool ALLDAY,bool FindUser,bool Aux, string StoreLog[21][10]
                    , int day,bool idledisplay,int rowinaday, bool actionsmorethan
                    , int action, bool Specificport,int specificport,bool USEREXCEPT, bool jumpport, int portfrom, int portend
                    , bool specificday,bool jumpday,int dayfrom,int dayend, int totalpolicy, bool blocksametime,int sametimeblock,  bool boolcontinuous, int continuoustimes
                    , bool rules3,int rules3time,bool defaults,bool jumpspecificport, int PORTS[21],int totalport
                    ,bool jumpspecificday,int totalday,int numberofday,int daysrecordjump[10]
                   )
{
    bool trigger= false;
    string actions="";
    if(Aw)
    {
        actions = actions+"w";
    }
    if(Ax)
    {
        actions = actions+"x";
    }
    if(Ar)
    {
        actions = actions+"r";
    }
    int start=0,loop=21, loop2 = 10, start2 =0;
    string record [21][10];
    string temp_record;
    string FINDSPECIFICUSERATALLDIFFERENTPORT[30][10];
    for(int i = start ; i<loop ; i++)
    {
        for(int j = start2 ; j<loop2 ; j++)
        {
            record[i][j] = StoreLog[i][j];
        }
    }

    int pointer =0;
    int counter=0;
    for(int i = 0 ; i< 21; i++)  // port
    {
        for(int j = 0 ; j < 60 ; j=j+2 )
        {
            for( int k = 0 ; k<10; k++)   // day
            {

                FINDSPECIFICUSERATALLDIFFERENTPORT[j/2][k]=FINDSPECIFICUSERATALLDIFFERENTPORT[j/2][k]+record[i][k].substr(j,2);
            }
        }
    }
    string verify[21] { "NULL" };
    if(ALLPORT == true || Specificport == true)
    {
        start=0,loop=21 ;
    }

    else if (jumpport == true)
    {
        start=portfrom;
        loop=portend+1;
    }
    if( (ALLDAY == true && jumpport==false) || (specificday == true && jumpport== false))
    {
        start=0,loop=21 ;
    }
    else if(jumpday == true)
    {
        start2=dayfrom;
        loop2=dayend;
    }

    if(jumpspecificport == true )
    {
        start=0;
        loop = totalport;
    }

    if(jumpspecificday == true )
    {
        start2=0;
        loop2 = totalday;
    }

    int oout=0;
    for(int i =start ; i<loop ; i++)
    {

        int iout=0;
        for(int j = start2 ; j<loop2 ; j++)
        {
            if (ALLDAY == false && specificday == true && jumpspecificday ==false )           //if specific day
            {
                j=day;
                temp_record = StoreLog[i][j];
            }
            else
            {
                temp_record = StoreLog[i][j];
            }
            if( ALLPORT ==false && Specificport == true && jumpspecificport==false) //if specific port
            {
                i = specificport;
                temp_record = StoreLog[i][j];
            }
            else
            {
                temp_record = StoreLog[i][j];
            }

            int temp,temp1;
            if(jumpspecificday)
            {
                //temp_record = StoreLog[i][j];
                temp1=daysrecordjump[iout];
                temp_record=StoreLog[i][temp1];
            }

            if(jumpspecificport == true ) //if specific port
            {
                //temp_record = StoreLog[i][j];
                temp=PORTS[oout];
                temp=temp-4000;
                temp_record=StoreLog[temp][j];
            }
            int counterport;
            int counterday;
            if(blocksametime ==false && rules3 == false && jumpspecificport ==false)
            {
                counterport=i;
                counterday=j;
            }
            else if(jumpspecificport == true && !jumpspecificday && blocksametime==false && rules3==false)
            {
                counterport=temp;
                counterday=j;
            }
            else if(jumpspecificday == true && !jumpspecificport&& blocksametime==false && rules3==false)
            {

                counterport=i;
                counterday=temp1;
            }
            else if(jumpspecificport && jumpspecificday)
            {
                temp_record=StoreLog[temp][iout];
                counterport=temp;
                counterday=temp1;
            }
            if(Ra == true)
            {
                USER="X";
                checkRa(temp_record, Ar, Aw, Ax, actionsmorethan,action, totalpolicy, FINDSPECIFICUSERATALLDIFFERENTPORT,  boolcontinuous,  continuoustimes,blocksametime,sametimeblock,defaults,counterport,counterday);             //record anonymous user and all read , write ,execution
            }
            else if(Au == true)
            {
                USER="ABCDEGFHIJKLMXZ";
                checkAu(temp_record, Ar, Aw, Ax,actionsmorethan,action,totalpolicy,FINDSPECIFICUSERATALLDIFFERENTPORT, boolcontinuous, continuoustimes,blocksametime, sametimeblock,defaults,counterport,counterday);
            }
            else if(FindUser == true  )
            {
                for(int i = 0; i < USER.length() ; i++)
                {
                    string temp;
                    temp = USER[i];
                    CheckUser(temp_record, Ar, Aw, Ax,temp,idledisplay,rowinaday, actionsmorethan,action,totalpolicy,FINDSPECIFICUSERATALLDIFFERENTPORT,  boolcontinuous,  continuoustimes,blocksametime, sametimeblock,defaults, totalport, jumpspecificport,PORTS,counterport,counterday);
                }
                if(defaults)
                {
                    cout<<endl;
                }
            }
            else if (Aux == true )
            {
                string temp="ABCDEFGHIJKLMXZ";
                string target= "ABCDEFGHIJKLM";
                char a ;
                for( int d = 0 ; d < target.length(); d++ )
                {
                    a = target[d];
                    for(int i = 0 ; i<temp.length(); i++)
                    {
                        if(temp[i] == a)
                        {
                            temp[i]='\0';
                        }
                    }
                }
                USER=temp;
                recordExceptAnonymous(temp_record, Ar, Aw, Ax, actionsmorethan,action, USER,totalpolicy,FINDSPECIFICUSERATALLDIFFERENTPORT, boolcontinuous,  continuoustimes, blocksametime, sametimeblock,defaults,counterport,counterday);
            }

            else if(USEREXCEPT==true)
            {
                string temp="ABCDEFGHIJKLMXZ";
                if(trigger==false)
                {
                    string target = USER;
                    char a ;
                    for( int d = 0 ; d < target.length(); d++ )
                    {
                        a = target[d];
                        for(int i = 0 ; i<temp.length(); i++)
                        {
                            if(temp[i] == a)
                            {
                                temp[i]='\0';
                            }
                        }
                    }
                    USER=temp;
                    trigger=true;
                }
                recordExceptAnonymous(temp_record, Ar, Aw, Ax, actionsmorethan,action, USER,totalpolicy,FINDSPECIFICUSERATALLDIFFERENTPORT, boolcontinuous,  continuoustimes, blocksametime, sametimeblock,defaults,counterport,counterday);
            }
            else if(idle== true || idledisplay == true)
            {
                USER = "Z";
                CheckUser(temp_record, Ar, Aw, Ax,USER,idledisplay,rowinaday, actionsmorethan,action,totalpolicy,FINDSPECIFICUSERATALLDIFFERENTPORT,  boolcontinuous,  continuoustimes,blocksametime, sametimeblock,defaults, totalport,  jumpspecificport,  PORTS,counterport,counterday);
            }
            if(jumpspecificday == true)
            {
                iout++;
                continue;
            }
            else if(jumpspecificday == true && iout ==loop2-1 )
            {
                break;
            }
            else if(specificday == true && ALLDAY ==false && jumpday == false)
            {
                break;
            }
        }
        if(blocksametime == false && rules3 == false )
        {
        }
        if(jumpspecificport == true)
        {
            oout++;
            continue;
        }
        else if(Specificport==true && ALLPORT == false && jumpport==false )
        {
            break;
        }
    }
    if(blocksametime)
    {
        RecordSameTimeSamePort(FINDSPECIFICUSERATALLDIFFERENTPORT,USER, sametimeblock,actions, totalpolicy,jumpspecificday,totalday,daysrecordjump);
    }
    else if (rules3)
    {

        RolesOf_TheDay( StoreLog, USER,  rules3time, actions,totalpolicy,jumpspecificday,totalday,daysrecordjump, totalport, PORTS, jumpspecificport,  jumpday,  dayfrom,  dayend,  jumpport,  portfrom,  portend);
    }
}

void recordExceptAnonymous(string temprecord, bool Ar,bool Aw,bool Ax,bool actionsmorethan,int action,string USER,int totalpolicy,string FINDSPECIFICUSERATALLDIFFERENTPORT[30][10],bool boolcontinuous, int continuoustimes,bool blocksametime,int sametimeblock,bool defaults,int counterport,int counterday)
{
    ofstream log("logs.txt",ios::app);
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    string a = temprecord;
    string rawdata=temprecord;
    string target = USER;
    int pointer;
    int counter;
    do
    {
        std::size_t found =a.find(target,pointer);
        counter= 0;
        if (found!=std::string::npos)
        {
            a =  a.substr(0,found) + a.substr(found+2);
            counter =1;
        }
    }
    while (counter != 0 );
    temprecord = a;

    string temp =temprecord, execute="x", read="r", write="w";
    temprecord = "";
    pointer = 0;
    string finalstring,temprecords;
    counter =0;
    do                                     //find port needed or not
    {
        counter =0;
        std::size_t found =temp.find(read,pointer);
        std::size_t found1 =temp.find(write,pointer);
        std::size_t found2 =temp.find(execute,pointer);
        if( found1 < found )
        {
            found = found1 ;
        }
        if ( found2 < found1 )
        {
            found1 = found2 ;
        }
        if(found2 < found)
        {
            found = found2;
        }
        if (found!=std::string::npos)
        {
            temprecord = temp.substr(found-1,2);
            pointer = found + 1;
            counter =1;

            if( Ar == true )
            {
                //pointer = 0;
                std::size_t found =temprecord.find(read,0);
                if (found!=std::string::npos)
                {
                    temprecords =  temprecord.substr(0,2);
                    finalstring = finalstring + temprecords;
                }
            }

            if(Aw ==true )
            {
                // pointer = 0;
                std::size_t found =temprecord.find(write,0);
                if (found!=std::string::npos)
                {
                    temprecords =  temprecord.substr(0,2);
                    finalstring = finalstring + temprecords;
                }
            }

            if(Ax ==true )
            {
                std::size_t found =temprecord.find(execute,0);
                if (found!=std::string::npos)
                {
                    temprecords =  temprecord.substr(0,2);
                    finalstring = finalstring + temprecords;
                }
            }
        }
    }
    while(counter!=0);
    int length = finalstring.length() / 2;
    if(actionsmorethan==true)
    {
        if(length==0 || length < action )
        {
            cout<<"It occur "<<length<<" times only .  Filtered Traffic: "<<finalstring;
        }
        else if(length >= action  )
        {
            SetConsoleTextAttribute(hConsole, 12);
            if( counterport<=9 )
            {
                cout<<"On port 400"<<counterport<<" on Day "<<counterday<<" ";
                log<<LOGDATA[5]<<counterport<<LOGDATA[7]<<counterday;
            }
            else
            {
                cout<<"On port 40"<<counterport<<" on Day "<<counterday<<" ";
                log<<LOGDATA[6]<<counterport<<LOGDATA[7]<<counterday;
            }
            cout<<"BASELINE ALERT : Action more than "<<action<<" . It occur "<< length<<" times . Filtered Traffic: "<<finalstring ;
            SetConsoleTextAttribute(hConsole, 7);

            log<<LOGDATA[8]<<totalpolicy<<LOGDATA[9]<<length<<LOGDATA[10]<<finalstring<<endl;
        }
    }
    else if( boolcontinuous == true)
    {
        string a=USER;
        for(int i =0; i< a.length() ; i++)
        {
            USER=a[i];
            SPECIFIC_EXCEPT_User_Continue( rawdata,  boolcontinuous, continuoustimes, Aw, Ax, Ar,counterport,counterday,totalpolicy,USER);
        }

    }
    else if(defaults== true)
    {
        if(finalstring.compare("")==0)
        {
            SetConsoleTextAttribute(hConsole, 12);
            cout<<"NULL";
            SetConsoleTextAttribute(hConsole, 7);
        }
        else
        {
            cout<<finalstring;
            if( counterport<=9 )
            {
                cout<<"On port 400"<<counterport<<" on Day "<<counterday<<" ";
                log<<LOGDATA[5]<<counterport<<LOGDATA[7]<<counterday;
            }
            else
            {
                cout<<"On port 40"<<counterport<<" on Day "<<counterday<<" ";
                log<<LOGDATA[6]<<counterport<<LOGDATA[7]<<counterday;
            }
            cout<<"Filtered Traffic: "<<finalstring<<endl;
            log<<LOGDATA[8]<<totalpolicy<<LOGDATA[11]<<finalstring<<endl;
        }
    }

}

void CheckUser(string temprecord,bool Ar,bool Aw,bool Ax,string USER,bool idledisplay,int rowinaday,bool actionsmorethan,int action,int totalpolicy,string FINDSPECIFICUSERATALLDIFFERENTPORT[30][10], bool boolcontinuous, int continuoustimes,bool blocksametime,int sametimeblock,bool defaults,int totalport, bool jumpspecificport, int PORTS[21],int counterport,int counterday)

//record specific user
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE); //console colour
    ofstream log("logs.txt",ios::app);
    string temp =temprecord, execute=USER + "x", read=USER+"r", write=USER+"w";
    string rawdata=temprecord;
    temprecord = "";
    string permission="";
    if(Ar)
    {
        permission=permission+"r";
    }
    if(Ax)
    {
        permission=permission+"x";
    }
    if(Aw)
    {
        permission=permission+"w";
    }
    int pointer = 0;
    string finalstring,temprecords;
    int counter =0;
    do                                     //find port needed or not
    {
        counter =0;
        std::size_t found =temp.find(USER,pointer);
        if (found!=std::string::npos)
        {
            temprecord = temp.substr(found,2);
            pointer = found + 1;
            counter =1;

            if( Ar == true )
            {
                //pointer = 0;
                std::size_t found =temprecord.find(read,0);
                if (found!=std::string::npos)
                {
                    temprecords =  temprecord.substr(0,2);
                    finalstring = finalstring + temprecords;

                }
            }

            if(Aw ==true )
            {
                // pointer = 0;
                std::size_t found =temprecord.find(write,0);
                if (found!=std::string::npos)
                {
                    temprecords =  temprecord.substr(0,2);
                    finalstring = finalstring + temprecords;
                }
            }

            if(Ax ==true )
            {
                std::size_t found =temprecord.find(execute,0);
                if (found!=std::string::npos)
                {
                    temprecords =  temprecord.substr(0,2);
                    finalstring = finalstring + temprecords;
                }
            }
        }
    }
    while(counter!=0);
    int length = finalstring.length()/2;
    if(idledisplay == true)
    {
        if(length==0 || length < rowinaday )
        {

            cout<<"\nNULL , it occur only "<<length<<" times . ";

        }
        else if(length >= rowinaday  )
        {
            SetConsoleTextAttribute(hConsole, 12);
            if( counterport<=9 )
            {
                cout<<"On port 400"<<counterport<<" on Day "<<counterday<<" ";
                log<<LOGDATA[5]<<counterport<<LOGDATA[7]<<counterday<<" ";
            }
            else
            {
                cout<<"On port 40"<<counterport<<" on Day "<<counterday<<" ";
                log<<LOGDATA[6]<<counterport<<LOGDATA[7]<<counterday<<" ";
            }
            cout<<"BASELINE ALERT : Inactive more than or equal "<<rowinaday<<" . It occur "<< length<<" times . Filtered packets : "<<finalstring<<"";
            SetConsoleTextAttribute(hConsole, 7);
            log<<LOGDATA[8]<<totalpolicy<<LOGDATA[9]<<length<<LOGDATA[10]<<finalstring<<endl;
        }

    }
    else if(actionsmorethan==true)
    {
        if(length==0 || length < action )
        {
            cout<<"\nIt occur "<<length<<" times only .  Filtered Traffic: "<<finalstring ;
        }
        else if(length >= action  )
        {
            SetConsoleTextAttribute(hConsole, 12);
            if( counterport<=9 )
            {
                cout<<"On port 400"<<counterport<<" on Day "<<counterday<<" ";
                log<<LOGDATA[5]<<counterport<<LOGDATA[7]<<counterday;
            }
            else
            {
                cout<<"On port 40"<<counterport<<" on Day "<<counterday<<" ";
                log<<LOGDATA[6]<<counterport<<LOGDATA[7]<<counterday;
            }
            cout<<"\nBASELINE ALERT : Action more than "<<action<<" . It occur "<< length<<" times . Filtered Traffic: "<<finalstring;
            SetConsoleTextAttribute(hConsole, 7);
            log<<LOGDATA[8]<<totalpolicy<<LOGDATA[9]<<length<<LOGDATA[10]<<finalstring<<endl;
        }

    }
    else if(idledisplay == false && actionsmorethan == false && defaults==true)
    {
        if(finalstring.compare("")==0)
        {
            SetConsoleTextAttribute(hConsole, 12);
            cout<<"NULL";
            SetConsoleTextAttribute(hConsole, 7);
        }
        else
        {
            cout<<finalstring;
            if( counterport<=9 )
            {
                cout<<"On port 400"<<counterport<<" on Day "<<counterday<<" ";
                log<<LOGDATA[5]<<counterport<<LOGDATA[7]<<counterday;
            }
            else
            {
                cout<<"On port 40"<<counterport<<" on Day "<<counterday<<" ";
                log<<LOGDATA[6]<<counterport<<LOGDATA[7]<<counterday;
            }
            cout<<"Filtered Traffic: "<<finalstring<<endl;
            log<<LOGDATA[8]<<totalpolicy<<LOGDATA[10]<<finalstring<<endl;
        }
    }
    else if( boolcontinuous == true)
    {
        SPECIFIC_User_Continue(rawdata,  boolcontinuous, continuoustimes, Aw, Ax, Ar,counterport,counterday, totalpolicy,USER);
    }

}

//Record only ANONYMOUS USER
void checkRa(string temprecord, bool Ar,bool Aw,bool Ax, bool actionsmorethan,int action,int totalpolicy,string FINDSPECIFICUSERATALLDIFFERENTPORT[30][10], bool boolcontinuous, int continuoustimes,bool blocksametime,int sametimeblock,bool defaults,int counterport,int counterday)
{
    ofstream log("logs.txt",ios::app);
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE); //console colour
    //  cout<<"temprecord is "<<temprecord<<endl;
    string temp =temprecord;
    char SPECIFICUSER = 'X';
    string permission="";
    if(Ar)
    {
        permission=permission+"r";
    }
    if(Ax)
    {
        permission=permission+"x";
    }
    if(Aw)
    {
        permission=permission+"w";
    }
    temprecord = "";
    string temprecords;
    int pointer = 0;
    int counter =0;
    string finalstring="";
    do                                     //find port needed or not
    {
        counter =0;
        std::size_t found =temp.find("X",pointer);
        if (found!=std::string::npos)
        {
            temprecord =  temp.substr(found,2);
            pointer = found + 1;
            counter =1;

            if( Ar == true )
            {
                std::size_t found =temprecord.find("Xr",0);
                if (found!=std::string::npos)
                {
                    finalstring = finalstring + temprecord;
                }
            }

            if(Aw ==true )
            {
                std::size_t found =temprecord.find("Xw",0);
                if (found!=std::string::npos)
                {
                    finalstring = finalstring + temprecord;
                }
            }

            if(Ax ==true )
            {
                std::size_t found =temprecord.find("Xx",0);
                if (found!=std::string::npos)
                {

                    finalstring = finalstring + temprecord;
                }
            }
        }
    }
    while(counter!=0);
    int length = finalstring.length() / 2;
    if(actionsmorethan==true)
    {
        if(length==0 || length < action )
        {
            cout<<"It occur "<<length<<" times only .  Filtered Traffic: "<<finalstring ;
        }
        else if(length >= action  )
        {
            SetConsoleTextAttribute(hConsole, 12);
            if( counterport<=9 )
            {
                cout<<"On port 400"<<counterport<<" on Day "<<counterday<<" ";
                log<<LOGDATA[5]<<counterport<<LOGDATA[7]<<counterday;
            }
            else
            {
                cout<<"On port 40"<<counterport<<" on Day "<<counterday<<" ";
                log<<LOGDATA[6]<<counterport<<LOGDATA[7]<<counterday;
            }
            cout<<"BASELINE ALERT : Action more than "<<action<<" . It occur "<< length<<" times . Filtered Traffic: "<<finalstring ;
            SetConsoleTextAttribute(hConsole, 7);
            log<<LOGDATA[8]<<totalpolicy<<LOGDATA[9]<<length<<LOGDATA[12]<<". Filtered Traffic: "<<finalstring<<endl;
        }

    }
    else if( boolcontinuous == true)
    {
        blockinarowcontinue( finalstring,  boolcontinuous, continuoustimes, Aw, Ax, Ar,counterport,counterday,totalpolicy);
    }

    else if(defaults== true)
    {
        if(finalstring.compare("")==0)
        {
            SetConsoleTextAttribute(hConsole, 12);
            cout<<"NULL";
            SetConsoleTextAttribute(hConsole, 7);
        }
        else
        {
            if( counterport<=9 )
            {
                cout<<"On port 400"<<counterport<<" on Day "<<counterday<<" ";
                log<<LOGDATA[5]<<counterport<<LOGDATA[7]<<counterday;
            }
            else
            {
                cout<<"On port 40"<<counterport<<" on Day "<<counterday<<" ";
                log<<LOGDATA[6]<<counterport<<LOGDATA[7]<<counterday;
            }
            cout<<"Filtered Traffic: "<<finalstring<<endl;
            log<<LOGDATA[8]<<totalpolicy<<LOGDATA[9]<<length<<LOGDATA[10]<<finalstring<<endl;
        }
    }

}

//Record All Users
void checkAu(string temprecord, bool Ar,bool Aw,bool Ax, bool actionsmorethan,int action,int totalpolicy,string FINDSPECIFICUSERATALLDIFFERENTPORT[30][10], bool boolcontinuous, int continuoustimes,bool blocksametime,int sametimeblock,bool defaults,int counterport,int counterday)
{
    ofstream log("logs.txt",ios::app);
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE); //console colour
    string USER ="ABCDEFGHIJKLMXZ";
    string actions = "wrx";
    string temp =temprecord, execute="x", read="r", write="w";
    temprecord = "";
    int pointer = 0;
    string finalstring,temprecords;
    int counter =0;
    do                                     //find port needed or not
    {
        counter =0;
        std::size_t found =temp.find(read,pointer);
        std::size_t found1 =temp.find(write,pointer);
        std::size_t found2 =temp.find(execute,pointer);

        if( found1 < found )
        {
            found = found1 ;
        }
        if ( found2 < found1 )
        {
            found1 = found2 ;
        }
        if(found2 < found)
        {
            found = found2;
        }

        if (found!=std::string::npos)
        {
            temprecord = temp.substr(found-1,2);
            pointer = found + 1;
            counter =1;

            if( Ar == true )
            {
                //pointer = 0;
                std::size_t found =temprecord.find(read,0);
                if (found!=std::string::npos)
                {
                    temprecords =  temprecord.substr(0,2);
                    finalstring = finalstring + temprecords;
                }
            }

            if(Aw ==true )
            {
                // pointer = 0;
                std::size_t found =temprecord.find(write,0);
                if (found!=std::string::npos)
                {

                    temprecords =  temprecord.substr(0,2);
                    finalstring = finalstring + temprecords;

                }
            }

            if(Ax ==true )
            {
                std::size_t found =temprecord.find(execute,0);
                if (found!=std::string::npos)
                {
                    temprecords =  temprecord.substr(0,2);
                    finalstring = finalstring + temprecords;

                }
            }
        }
    }
    while(counter!=0);
    int length = finalstring.length()/2;
    if(actionsmorethan==true)
    {
        if(length==0 || length < action )
        {
            cout<<"It occur "<<length<<" times only .  Filtered Traffic: "<<finalstring;
        }
        else if(length >= action  )
        {
            SetConsoleTextAttribute(hConsole, 12);
            if( counterport<=9 )
            {
                cout<<"On port 400"<<counterport<<" on Day "<<counterday<<" ";
                log<<LOGDATA[5]<<counterport<<LOGDATA[7]<<counterday<<" ";
            }
            else
            {
                cout<<"On port 40"<<counterport<<" on Day "<<counterday<<" ";
                log<<LOGDATA[6]<<counterport<<LOGDATA[7]<<counterday<<" ";
            }

            cout<<"BASELINE ALERT : Action more than "<<action<<" . It occur "<< length<<" times . Filtered Traffic: "<<finalstring;
            SetConsoleTextAttribute(hConsole, 7);
            log<<LOGDATA[8]<<totalpolicy<<LOGDATA[13]<<action <<LOGDATA[14]<<length<<LOGDATA[12]<<" Filtered Packets :"<<finalstring<<endl;
        }
    }
    else if( boolcontinuous == true)
    {
        blockinarowcontinue( finalstring,  boolcontinuous, continuoustimes, Aw, Ax, Ar,counterport,counterday,totalpolicy );
    }
    else if(defaults== true)
    {
        if(finalstring.compare("")==0)
        {
            SetConsoleTextAttribute(hConsole, 12);
            //cout<<"NULL";
            SetConsoleTextAttribute(hConsole, 7);
        }
        else
        {
            if( counterport<=9 )
            {
                cout<<"On port 400"<<counterport<<" on Day "<<counterday<<" ";
                log<<LOGDATA[5]<<counterport<<LOGDATA[7]<<counterday<<" ";
            }
            else
            {
                cout<<"On port 40"<<counterport<<" on Day "<<counterday<<" ";
                log<<LOGDATA[6]<<counterport<<LOGDATA[7]<<counterday<<" ";
            }

            log<<LOGDATA[8]<<totalpolicy<<LOGDATA[9]<<length<<LOGDATA[10]<<finalstring<<endl;
            cout<<"Filtered Traffic: "<<finalstring<<endl;
        }
    }
}

//Rules 1 for USER EXCEPT AuX IN DYNAMICGRAMMER.TXT[11]
void SPECIFIC_EXCEPT_User_Continue(string finalstring,bool boolcontinuoustimes, int times,bool Aw, bool Ax, bool Ar,int counterport,int counterday,int totalpolicy,string USER)   //rules 1
{
    ofstream log("logs.txt",ios::app);
    int appeartimes=0;
    bool skip = false;
    string storeuser;
    char COMPAREVALUE ='Y';

    for(int i = 0; i<finalstring.length(); i=i+2)
    {
        char temporary = finalstring[i];
        if(COMPAREVALUE=='Y' || (COMPAREVALUE!='Y'  && temporary==COMPAREVALUE))
        {
            COMPAREVALUE=finalstring[i];
            appeartimes++;
        }
        else if(temporary != COMPAREVALUE)
        {
            if(appeartimes >= times &&COMPAREVALUE == USER[0])
            {
                if( counterport<=9 )
                {
                    cout<<"On port 400"<<counterport<<" on Day "<<counterday<<" ";
                    log<<LOGDATA[5]<<counterport<<LOGDATA[7]<<counterday<<" ";
                }
                else
                {
                    cout<<"On port 40"<<counterport<<" on Day "<<counterday<<" ";
                    log<<LOGDATA[6]<<counterport<<LOGDATA[7]<<counterday<<" ";
                }
                cout<<"\t["<<COMPAREVALUE<<"] appear more than ["<<times<<"] and it occur ["<<appeartimes<<"]  continuously in a block  Filtered packets :"<<finalstring<<endl;
                log<<LOGDATA[8]<<totalpolicy<<LOGDATA[19];
                log<<"\t["<<COMPAREVALUE<<"] appear more than ["<<times<<"] and it occur ["<<appeartimes<<"]  continuously in a block   Filtered packets :"<<finalstring<<endl;
            }
            COMPAREVALUE=finalstring[i];
            appeartimes=1 ;
        }

        if(i == finalstring.length()-1 && appeartimes >= times)
        {
            cout<<"Matches "<<COMPAREVALUE;
        }
    }
}

//Rules 1 for SPECIFY USER IN DYNAMICGRAMMER.TXT[13]
void SPECIFIC_User_Continue(string finalstring,bool boolcontinuoustimes, int times,bool Aw, bool Ax, bool Ar,int counterport,int counterday,int totalpolicy,string USER)   //rules 1
{
    ofstream log("logs.txt",ios::app);
    int appeartimes=0;
    bool skip = false;
    string storeuser;
    char COMPAREVALUE ='Y';

    for(int i = 0; i<finalstring.length(); i=i+2)
    {
        char temporary = finalstring[i];
        if(COMPAREVALUE=='Y' || (COMPAREVALUE!='Y'  && temporary==COMPAREVALUE))
        {
            COMPAREVALUE=finalstring[i];
            appeartimes++;
        }
        else if(temporary != COMPAREVALUE)
        {
            if(appeartimes >= times &&COMPAREVALUE == USER[0])
            {
                if( counterport<=9 )
                {
                    cout<<"On port 400"<<counterport<<" on Day "<<counterday<<" ";
                    log<<LOGDATA[5]<<counterport<<LOGDATA[7]<<counterday<<" ";
                }
                else
                {
                    cout<<"On port 40"<<counterport<<" on Day "<<counterday<<" ";
                    log<<LOGDATA[6]<<counterport<<LOGDATA[7]<<counterday<<" ";
                }
                cout<<"\t["<<COMPAREVALUE<<"] appear more than ["<<times<<"] and it occur ["<<appeartimes<<"]  continuously in a block  Filtered packets :"<<finalstring<<endl;
                log<<LOGDATA[8]<<totalpolicy<<LOGDATA[19];
                log<<"\t["<<COMPAREVALUE<<"] appear more than ["<<times<<"] and it occur ["<<appeartimes<<"]  continuously in a block  Filtered packets :"<<finalstring<<endl;
            }
            COMPAREVALUE=finalstring[i];
            appeartimes=1 ;
        }

        if(i == finalstring.length()-1 && appeartimes >= times)
        {
            cout<<"Matches "<<COMPAREVALUE;
        }
    }
}

//Rules 1 for ALL USER
void blockinarowcontinue(string finalstring,bool boolcontinuoustimes, int times,bool Aw, bool Ax, bool Ar,int counterport,int counterday,int totalpolicy )  //rules 1
{
    ofstream log("logs.txt",ios::app);
    int appeartimes=0;
    string storeuser;
    char COMPAREVALUE ='Y';
    for(int i = 0; i<finalstring.length(); i=i+2)
    {
        char temporary = finalstring[i];
        if(COMPAREVALUE=='Y' || (COMPAREVALUE!='Y'  && temporary==COMPAREVALUE))
        {
            COMPAREVALUE=finalstring[i];
            appeartimes++;
        }
        else if(temporary != COMPAREVALUE)
        {
            if(appeartimes >= times)
            {
                if( counterport<=9 )
                {
                    cout<<"On port 400"<<counterport<<" on Day "<<counterday<<" ";
                    log<<LOGDATA[5]<<counterport<<LOGDATA[7]<<counterday<<" ";
                }
                else
                {
                    cout<<"On port 40"<<counterport<<" on Day "<<counterday<<" ";
                    log<<LOGDATA[6]<<counterport<<LOGDATA[7]<<counterday<<" ";
                }
                cout<<"\t["<<COMPAREVALUE<<"] appear more than ["<<times<<"] and it occur ["<<appeartimes<<"]  continuously in a block  Filtered packets :"<<finalstring<<endl;
                log<<LOGDATA[8]<<totalpolicy<<LOGDATA[19];
                log<<"\t["<<COMPAREVALUE<<"] appear more than ["<<times<<"] and it occur ["<<appeartimes<<"]  continuously in a block  Filtered packets :"<<finalstring<<endl;
            }
            COMPAREVALUE=finalstring[i];
            appeartimes=1 ;
        }

        if(i == finalstring.length()-1 && appeartimes >= times)
        {
            cout<<"Matches "<<COMPAREVALUE;
        }
    }
}

//ONLY CAN USE for ALL USER rules 4
void RecordSameTimeSamePort(string FINDSPECIFICUSERATALLDIFFERENTPORT[30][10],string USER, int sametimeblock,string action,int totalpolicy,bool jumpspecificday, int totalday,int daysrecordjump[10])
{
    ofstream log("logs.txt",ios::app);
    for(int j = 0 ; j < 10 ; j ++)
    {
        bool daysstop=false;
        if(jumpspecificday)
        {
            int a=0;
            for(int k =0; k <totalday ; k++)
            {
                if(daysrecordjump[k] != j)
                {
                    if(a == totalday-1)
                    {
                        daysstop=true;
                        break;
                    }
                    a++;
                }
            }
        }
        if(daysstop)
        {
            continue;
        }
        for (int i = 0 ; i < 30 ; i ++)
        {
            string temp =  FINDSPECIFICUSERATALLDIFFERENTPORT[i][j];
            cout<<"Day ["<<j<<"] Time [";
            if(i<=9)
                cout<<"0";  // just alignment
            cout<<i<<"] "<<FINDSPECIFICUSERATALLDIFFERENTPORT[i][j] << " ";
            string userRestriction = USER;
            string actionRestriction = action;
            //typedef std::map<std::pair<char, char>, int > Maptype;
            map<char, int> m;
            for (int i = 0; i < temp.length(); i+=2)
            {
                char user = temp[i];
                char action = temp[i + 1];
                if (userRestriction.find(user) != std::string::npos && actionRestriction.find(action) != std::string::npos)
                {
                    m[user]++;
                }
            }
            cout<<"Result --> ";
            int counter =0;
            int check=0;
            bool stop=false;
            for ( auto it:m)
            {

                if (it.second >= sametimeblock)
                {
                    cout << it.first << ':' << it.second;
                    log<<LOGDATA[8]<<totalpolicy<<LOGDATA[19]<<LOGDATA[17]<<j<<LOGDATA[18];
                    if(i<=9)
                    {
                        log<<"0";
                    }
                    log<<i<<LOGDATA[19];
                    check=1;
                    log<< it.first <<LOGDATA[16]<<" "<< it.second<<" Filtered packets : "<<temp<<endl;
                }
            }
            cout<<endl;
        }
    }
}

void RolesOf_TheDay(string StoreLog[21][10],string USER, int rowoftheday,string action,int totalpolicy,bool jumpspecificday, int totalday,int daysrecordjump[10],int totalport,int PORTS[21],bool jumpspecificport, bool jumpday, int dayfrom, int dayend, bool jumpport, int portfrom, int portend)      // rules 3
{
    ofstream log("logs.txt",ios::app);
    for(int j = 0 ; j < 10 ; j ++)
    {
        bool daysstop=false;
        if(jumpspecificday)
        {
            int a=0;
            for(int k =0; k <totalday ; k++)
            {
                if(daysrecordjump[k] != j)
                {
                    if(a == totalday-1)
                    {
                        daysstop=true;
                        break;
                    }
                    a++;
                }
            }
        }
        else if(jumpday)
        {
            int u =dayfrom;
            for(int b= dayfrom; b < dayend ; b++)
            {
                if(b != j)
                {
                    if(u ==dayend-1)
                    {
                        daysstop=true;
                        break;
                    }
                    u++;
                }

            }
        }
        if(daysstop)
        {
            continue;
        }
        for (int i = 0 ; i < 21 ; i ++)
        {
            bool portstop=false;
            int l =0;
            if(jumpspecificport)
            {
                for(int h =0 ; h <=totalport ; h++)
                {
                    int temp=PORTS[h]-4000;
                    if(PORTS[h]-4000 !=i )
                    {
                        if(l==totalport-1)
                        {
                            portstop=true;
                            break;
                        }
                        l++;
                    }
                }
            }
            else if(jumpport)
            {
                int y =portfrom;
                for(int c= portfrom ; c <= portend ; c++)
                {
                    if(c != i)
                    {
                        if(y ==portend)
                        {
                            portstop=true;
                            break;
                        }
                        y++;
                    }

                }
            }
            if(portstop)
            {
                continue;
            }
            string temp =  StoreLog[i][j];
            cout<<"Day ["<<j<<"] Port [";
            if(i<=9)
                cout<<"0";  // just alignment

            cout<<i<<"] "<<StoreLog[i][j] << " ";
            string userRestriction = USER;
            string actionRestriction = action;
            //typedef std::map<std::pair<char, char>, int > Maptype;
            map<char, int> m;
            for (int i = 0; i < temp.length(); i+=2)
            {
                char user = temp[i];
                char action = temp[i + 1];
                if (userRestriction.find(user) != std::string::npos && actionRestriction.find(action) != std::string::npos)
                {
                    m[user]++;
                }
            }
            cout<<"Result --> ";
            for ( auto it:m)
            {
                if (it.second >= rowoftheday)
                {
                    cout << it.first << ':' << it.second;
                    log <<LOGDATA[8]<<totalpolicy<<LOGDATA[19]<<LOGDATA[17]<<j<<LOGDATA[19];
                    log<<LOGDATA[22]<<i<<LOGDATA[19]<<it.first <<LOGDATA[16]<<" "<< it.second <<"  Filtered packets :"<<temp<<endl;
                }
            }
            cout<<endl;
        }
    }
}

void readFiltering()
{
    bool rules=false,exe = false,read = false,write = false,more_or_equal=false, ports = false;
    bool trigger= false,no_actions=true,daysrequired=false,portrequired=false;
    ifstream readalert("alertpolicy.txt");
    if(!readalert.is_open())
    {
        cout<<"alertpolicy.txt is not found , program is quit "<<endl;
        exit(0);
    }
    int totalalert=1;
    string alert;
    while(!readalert.eof())
    {
        getline(readalert,alert);
        if(alert=="")
        {
            continue;
        }
        if (alert[0]=='#' && alert[1]!='#' && alert[2]!='#' || alert[0]=='#' && alert[1]=='#' && alert[2]=='#')
        {
            cout<<"-------------------------------------------------------------"<<endl;
            cout<<"Alert rules "<<totalalert<<" Skip"<<endl;
            totalalert++;
            continue;
        }
        int specificrules;
        cout<<"\n-------------------------------------------------------------\n\n";
        cout<<"Alert rules "<<totalalert<<endl;
        cout<<"Checklists :"<<endl;
        int pointer =0;
        int actions_more_ = 0;
        if(alert[0] == '#' && alert[1]=='#' && alert[2]!='#')
        {
            for(int i = 2; i <alert.length() ; i++ )
            {
                if(alert[i]=='#' && alert[i+1]=='#')
                {
                    cout<<"Comments message \""<<alert.substr(2,i-2)<<"\""<<endl;
                    alert=alert.substr(i+2,alert.length());
                    cout<<"Policy commands "<<alert<<endl;
                    break;
                }

            }
        }
        std::size_t found =alert.find(SPECIFICKEYWORDSGRAMMER[17],pointer);
        if (found!=std::string::npos)                                       //is rules required?
        {
            rules=true;
            string temp ;
            pointer = found + SPECIFICKEYWORDSGRAMMER[17].length();
            for (int i = found + SPECIFICKEYWORDSGRAMMER[17].length(); i<alert.length(); i++)
            {
                if(alert[i] == 32 || alert[i]==0)
                {
                    break;
                }
                else
                {
                    temp = temp+alert[i];
                }
            }
            specificrules=stoi(temp);
            cout<<"Record this rules "<<specificrules<<endl;

        }
        pointer = 0;
        found =alert.find(SPECIFICKEYWORDSGRAMMER[18],pointer);             //execute is required?
        if(found!=std::string::npos)
        {
            exe = true;
            no_actions=false;
            cout<<"Exe is required"<<endl;
        }
        pointer = 0;
        found =alert.find(SPECIFICKEYWORDSGRAMMER[19],pointer);            // write is required?
        if(found!=std::string::npos)
        {
            write=true;
            no_actions=false;
            cout<<"write is required"<<endl;
        }
        pointer = 0;
        found =alert.find(SPECIFICKEYWORDSGRAMMER[20],pointer);             //read is required ?
        if(found!=std::string::npos)
        {
            read=true;
            no_actions=false;
            cout<<"read is required"<<endl;
        }

        pointer = 0;
        found =alert.find(SPECIFICKEYWORDSGRAMMER[21],pointer);         //find how many times it trigger
        if(found!=std::string::npos)
        {
            more_or_equal=true;
            string temp =alert.substr(found+SPECIFICKEYWORDSGRAMMER[21].length(),2);
            actions_more_= stoi(temp);
            cout<<"Alert need to record "<<actions_more_<<" or above "<<endl;
        }

        int PORT[21];
        pointer = 0;
        int counter=0;
        int totalport = 0;
        found =alert.find(SPECIFICKEYWORDSGRAMMER[0],pointer);          //find specific port
        if (found!=std::string::npos)
        {
            portrequired = true;
            int length = SPECIFICKEYWORDSGRAMMER[0].length();
            string test;
            string port;
            int counter=0;
            for( int i = found+length ; i < alert.length()+1 ; i++)
            {
                if(alert[i]==32 || alert[i]==0)
                {
                    totalport++;
                    PORT[counter]=stoi(test);
                    counter++;
                    break;
                }
                else if(alert[i]==44)
                {
                    totalport++;
                    PORT[counter]=stoi(test);
                    counter++;
                    test="";
                }
                else
                {
                    test = test + alert[i];
                }
            }

            if(totalport > 1)
            {
                cout<<"Record port ";
            }
            for(int i = 0 ; i<totalport ; i++ )
            {
                cout<<PORT[i]<<" ";
            }
            cout<<endl;
        }
        int totalday=0;
        int daysrecordjump[10];
        pointer = 0;
        found = alert.find(SPECIFICKEYWORDSGRAMMER[9],pointer);             //record specific day
        if (found!=std::string::npos)
        {
            daysrequired= true;
            string test;
            for( int i = found+SPECIFICKEYWORDSGRAMMER[9].length() ; i <=alert.length() ; i++)
            {
                if(alert[i]==32 || alert[i]==0)
                {
                    daysrecordjump[totalday]=stoi(test);
                    totalday++;
                    break;
                }
                else if(alert[i]==44)
                {
                    daysrecordjump[totalday]=stoi(test);
                    test="";
                    totalday++;
                    continue;
                }
                else
                {
                    test=test+alert[i];
                }
            }

            cout<<"Days need to be records is ";
            for(int loop =0; loop < totalday ; loop++)
            {
                cout<<daysrecordjump[loop]<<"  ";
            }
            cout<<endl;

        }
        ifstream readlogfiles("logs.txt");
        if(!readlogfiles.is_open())
        {
            cout<<"Logs.txt is not found , program is quit "<<endl;
            exit(0);
        }
        while(!readlogfiles.eof())
        {
            string data;
            int atemp =0;
            int btemp =0;
            bool stop = false;
            bool bstop=false;
            getline(readlogfiles,data);
            if(data=="")
            {
                continue;
            }
            int count = 0;
            std::size_t found2 =data.find("Day ",count);
            if(found2!=std::string::npos)
            {
                string temp ;
                temp= data[found2+4];
                atemp= stoi(temp);
                for(int i = 0 ; i < totalday; i++)
                {
                    if(atemp == daysrecordjump[i])
                    {
                        stop = true;
                    }
                }
            }
            count=0;
            std::size_t found3 =data.find("On port ",count);
            if(found3!=std::string::npos)
            {
                string temp ;
                temp= data.substr(found3+8,4);
                btemp= stoi(temp);
                for(int i = 0 ; i < totalport; i++)
                {
                    if(btemp == PORT[i])
                    {
                        bstop = true;
                    }
                }
            }

            if(daysrequired && portrequired)            //if both required , such as days and port
            {
                if(stop && bstop)
                {
                }
                else
                {
                    continue;
                }
            }
            else if(daysrequired && !portrequired)          //if only day required
            {
                if(!stop)
                {
                    continue;
                }
            }
            else if(!daysrequired && portrequired)              //if only port required
            {
                if(!bstop)
                {
                    continue;
                }
            }
            int more_than_Actions;
            int rulescompare;
            if(rules == true)
            {
                int pointer =0;
                string a;
                found =data.find("Rules ",pointer);          //find specific port
                if (found!=std::string::npos)
                {
                    for(int i =0 ; i < data.length() ; i++)
                    {
                        if(data[found+6+i] == ']' || data[found+6+i] == 32 )
                        {
                            rulescompare=stoi(a);
                            break;
                        }
                        else
                        {
                            a = a+data[found+6+i] ;
                        }
                    }
                }
            }
            string record_of_the_port;
            string record_of_the_day;
            if(more_or_equal == true && specificrules==rulescompare)
            {
                int pointer =0;
                int pointer1 =0;
                string a;
                string temp;
                found=data.find("it occur [",pointer);          //find specific port
                std::size_t found1 = data.find("Filtered Packet :",pointer1);
                if(found == std::string::npos)
                {
                    trigger = true;
                }
                else if (found!=std::string::npos && trigger==false)     // if found it occur keyword
                {
                    if(data[found+11] == ']')
                    {
                        temp = data[found+10];
                    }
                    else
                    {
                        temp = data[found+10] + data[found+11];
                    }
                    more_than_Actions=stoi(temp);
                    pointer =0;
                    found=data.find("On port 40",pointer);      //get the string of port and days only
                    {
                        record_of_the_port = data[found+10];
                        record_of_the_port = record_of_the_port+data[found+11];
                    }
                    pointer =0;
                    found=data.find("on Day ",pointer);      //get the string of port and days only
                    {
                        record_of_the_day = data[found+7];
                    }
                    if(more_than_Actions>=actions_more_ )
                    {
                        cout<<"On rules "<<rulescompare<<" record trigger "<<actions_more_<<    " and it occur "<<more_than_Actions<<" on "<<"PORT 40"<<record_of_the_port<<" and on Day "<<record_of_the_day<<endl;
                    }
                }

                if(trigger == true)                         //find filtered packets required or not
                {
                    if (found1!=std::string::npos)         //if found filtered packet : keyword
                    {
                        temp = data.substr(found1+17,data.length()-found+17);
                        string a ;
                        for(int i =0 ; i<temp.length(); i++)
                        {
                            if(temp[i] == 'x' && exe==true)
                            {
                                a =a+ temp[i-1]+temp[i];
                            }
                            if(temp[i] == 'w' && write == true)
                            {
                                a =a+ temp[i-1]+temp[i];
                            }
                            if(temp[i] == 'r'&& read==true)
                            {
                                a =a+ temp[i-1]+temp[i];
                            }
                        }
                        temp=a;
                        found1=data.find("On port 40",pointer);      //get the string of port and days only
                        {
                            record_of_the_port = data[found1+10];
                            record_of_the_port = record_of_the_port+data[found1+11];
                        }
                        pointer =0;
                        found1=data.find("on Day ",pointer);      //get the string of port and days only
                        {
                            record_of_the_day = data[found1+7];
                        }
                        if(rulescompare==specificrules && temp.length()/2 >= actions_more_ )
                        {
                            cout<<"On rules "<<specificrules<<" on PORT 40"<<record_of_the_port<<" and on Day "<<record_of_the_day<<"and it got trigger it occur "<< temp.length()/2 <<" and baseline is "<<actions_more_<<endl;
                        }
                    }
                }


            }
        }
        readlogfiles.close();
        totalalert=totalalert+1;
    }
}
