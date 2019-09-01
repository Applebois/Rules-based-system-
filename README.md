#MD5:3d794d2cef229d49a6252ec9d3e03ed5 
making sure the dynamicgrammer.txt is this MD5 to prevent grammer changing , if grammer changed below keywords some might not functionable 

#USER RELATED
"AuX"  // record ALL USER except specific user

"A!X" // record ALL USER EXCEPT USER X (Anonymous)

"Au"  // record ALL USER INCLUDE ANONYMOUS

"-Su" // Record specific user 

"-Ra" //record any anonymous

"-idle" // check unactive port


# If didn't specify it will be ALL USER

######################################################################
#DAY & PORT RELATED

"-p"   // find specific port   // just 1 port only

"-Day" //find specific records on that day // 1 day only

"-p-" //all ports  ***no idea why i add this***

"-JP" // JUMP PORT such as "eg -JP4010-4015"

"-JD"  // JUMP days such as "eg . -JD3-5"

# If didn't mention by default it will be all days and all ports

#######################################################################

#Action

"-Ax"  //Any execution 			//Rules 2 example

"-Ar" //Any read

"-Aw" //Any write

#if didn't specify it will record non actions

#######################################################################

Support Actions    // IF DIDN'T SPECIFY IT WILL JUST RUN FILTERING BASE ON THE ACTIONS AND RAW TRAFFIC

"actions more than" //find inactive how many times more than or equal		// Check how many times the actions occur 

"inactive more than" //find inactive how many times more than or equal		// Same as actions more than but this only find INACTIVE Z

"-C" Continuous how many times such as ZxZxZrZwZw "eg . -C5" 5 represent threshold (Rules 1 example)  // Rules 1 ONLY FOR ALL PORT AND ALL DAY even it specify day and port will run all  

"#"  // comments the policy ("SKIP THE POLICY but must put the first character ")

"-blocksametime"  // Rules 4 find same times and day for their actions how many they have attached  eg "-blocksametime3" threshold is 3

"attach"    //Rules 3 find the users on that port and day actions how many times 
#############################################################################

MUST TAKE NOTES 

-C CANNOT SPECIFY THE USERS 
BLOCKSAMETIME & ATTACH CANNOT SPECIFY PORT & DAY
