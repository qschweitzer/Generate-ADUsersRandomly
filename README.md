# Generate-ADUsersRandomly
![Banner](https://user-images.githubusercontent.com/36896812/163008548-58acd368-fd28-448e-aca8-757f59d39d91.jpg)

Create Active Directory OU tree structure and generate users randomly with associate groups.
**DON'T USE IN PRODUCTION ENVIRONNEMENT**
This tool has been write to be used in some PoC.

## HOW TO USE
First, create your JSON configuration based on the SAMPLE_CONFIG.json file on this repository.
**!! JSON file must be beside the .PS1 or in a subfolder !!**
Next, simply starts the PS1 on an AD server or server with Active Directory powershell module and follow instructions.

**All users created are exported in a JSON file in C:\ADGeneration. His name contains the generation name choosed during script execution.**
