CREATE DATABASE CyberSecurity_Incident_Reports;

USE CyberSecurity_Incident_Reports;

SHOW TABLES;

-- Table: ORGANIZATION
CREATE TABLE ORGANIZATION(
    Victim_ID VARCHAR(255) PRIMARY KEY
);


-- Table: PERSON
CREATE TABLE PERSON(
    Last_Name VARCHAR(255),
    First_Name VARCHAR(255),
    SSN INT,
    Phone VARCHAR(255),
    Email VARCHAR(255),
    CONSTRAINT PK_PERSON PRIMARY KEY(SSN)
);


-- Table: CRIT_INFR_PRIV_SECTOR
CREATE TABLE CRIT_INFR_PRIV_SECTOR(
    Organization_or_Company_Name VARCHAR(255) PRIMARY KEY,
    Org_Type VARCHAR(255),
    Internal_Tracking_No VARCHAR(255),
    Victim_ID VARCHAR(255),
    FOREIGN KEY (Victim_ID) REFERENCES ORGANIZATION(Victim_ID)
);


-- Table: US_FED_GOV
CREATE TABLE US_FED_GOV(
    Federal_Agency VARCHAR(255),
    FSubagency VARCHAR(255),
    Internal_Tracking_No VARCHAR(255),
    Victim_ID VARCHAR(255),
    CONSTRAINT PK_US_FED_GOV PRIMARY KEY(Federal_Agency, FSubagency),
    FOREIGN KEY (Victim_ID) REFERENCES ORGANIZATION(Victim_ID)
);


-- Table: SLTT_GOV
CREATE TABLE SLTT_GOV(
    Subagency VARCHAR(255) PRIMARY KEY,
    Internal_Tracking_No VARCHAR(255),
    Victim_ID VARCHAR(255),
    FOREIGN KEY (Victim_ID) REFERENCES ORGANIZATION(Victim_ID)
);


-- Table: FOREIGN_GOV
CREATE TABLE FOREIGN_GOV(
    Country VARCHAR(255) PRIMARY KEY,
    National_CSIRT VARCHAR(255) CHECK (National_CSIRT IN ('Yes', 'No')),
    Internal_Tracking_NO VARCHAR(255),
    Victim_ID VARCHAR(255),
    FOREIGN KEY (Victim_ID) REFERENCES ORGANIZATION(Victim_ID)
);


-- Table: INDIVIDUAL
CREATE TABLE INDIVIDUAL(
    Last_Name VARCHAR(255),
    First_Name VARCHAR(255),
    SSN INT,
    Phone VARCHAR(255),
    Email VARCHAR(255),
    Victim_ID VARCHAR(255),
    FOREIGN KEY (Victim_ID) REFERENCES ORGANIZATION(Victim_ID),
    FOREIGN KEY (SSN) REFERENCES PERSON(SSN),
    CONSTRAINT PK_INDIVIDUAL PRIMARY KEY(SSN)
);


-- Table: CONTACT
CREATE TABLE CONTACT(
    Last_Name VARCHAR(255),
    First_Name VARCHAR(255),
    SSN INT,
    Phone VARCHAR(255),
    Email VARCHAR(255),
    Job_title VARCHAR(255),
    Alt_Phone INT,
    Mobile INT,
    Pager VARCHAR(255),
    Fax VARCHAR(255),
    FOREIGN KEY (SSN) REFERENCES PERSON(SSN)
);


-- Table: INCIDENT
CREATE TABLE INCIDENT(
    CISA_Incident_ID VARCHAR(255) PRIMARY KEY,
    Attack_Start_Date DATE,
    Attack_Start_Time TIMESTAMP,
    Attack_First_Detected_Date DATE,
    Attack_First_Detected_Time TIMESTAMP,
    Incident_Narrative VARCHAR(255),
    Attack_Ended VARCHAR(255) CHECK (Attack_Ended IN ('Yes', 'No')),
    Attack_Duration INT,
    Incident_Type VARCHAR(255),
    EFlag INT,
    CVE VARCHAR(255),
    Common_Name VARCHAR(255),
    MFlag INT,
    Malware_Type VARCHAR(255),
    Malware_Name VARCHAR(255),
    Signature VARCHAR(255),
    Description_I VARCHAR(255),
    CHECK (Attack_Start_Date <= Attack_First_Detected_Date),
    CHECK (Attack_Start_Time <= Attack_First_Detected_Time)
);

-- Table: REPORT
CREATE TABLE REPORT(
    Report_ID VARCHAR(255) PRIMARY KEY,
    Submission_Date DATE,
    Submission_Time TIMESTAMP,
    Estimated_Recovery_Time_Clock_Hours INT,
    Estimated_Recovery_Time_Staff_Hours INT,
    Estimated_Damage_Accounts VARCHAR(255),
    CISA_Incident_ID VARCHAR(255),
    FOREIGN KEY (CISA_Incident_ID) REFERENCES INCIDENT(CISA_Incident_ID)
);

-- Table: OBSERVED_ACTIVITY_NETWORK_LOCATION
CREATE TABLE OBSERVED_ACTIVITY_NETWORK_LOCATION(
    CISA_Incident_ID VARCHAR(255),
    Location_Part VARCHAR(255),
    CONSTRAINT PK_OBSERVED_ACTIVITY_NETWORK_LOCATION PRIMARY KEY(CISA_Incident_ID, Location_Part),
    FOREIGN KEY (CISA_Incident_ID) REFERENCES INCIDENT(CISA_Incident_ID)
);

-- Table: SUSPECTED_PERPETRATORS
CREATE TABLE SUSPECTED_PERPETRATORS(
    CISA_Incident_ID VARCHAR(255),
    Perpetrators VARCHAR(255),
    CONSTRAINT PK_SUSPECTED_PERPETRATORS PRIMARY KEY(CISA_Incident_ID, Perpetrators),
    FOREIGN KEY (CISA_Incident_ID) REFERENCES INCIDENT(CISA_Incident_ID)
);

-- Table: ANTIVIRUS
CREATE TABLE ANTIVIRUS(
    CISA_Incident_ID VARCHAR(255),
    Antivirus_Name VARCHAR(255),
    Detect_Malware VARCHAR(255) CHECK (Detect_Malware IN ('Yes', 'No')),
    Last_Updated DATE,
    CONSTRAINT PK_ANTIVIRUS PRIMARY KEY(CISA_Incident_ID, Antivirus_Name),
    FOREIGN KEY (CISA_Incident_ID) REFERENCES INCIDENT(CISA_Incident_ID)
);

-- Table: NETWORK_ACTIVITY
CREATE TABLE NETWORK_ACTIVITY(
    CISA_Incident_ID VARCHAR(255),
    Port_Number INT,
    Protocol_Name VARCHAR(255),
    Network_Activity_Type VARCHAR(255) CHECK (Network_Activity_Type IN ('Source', 'Destination')),
    CONSTRAINT PK_NETWORK_ACTIVITY PRIMARY KEY(CISA_Incident_ID, Port_Number),
    FOREIGN KEY (CISA_Incident_ID) REFERENCES INCIDENT(CISA_Incident_ID)
);

-- Creating the IMPACT_FACTOR table
CREATE TABLE IMPACT_FACTOR(
    CISA_Incident_ID VARCHAR(255),
    Impact_ID VARCHAR(64),
    Total_Impacted_Hosts INT,
    Total_Impacted_People INT,
    Functional_Impact VARCHAR(255),
    Information_Impact VARCHAR(255),
    Recoverability VARCHAR(255),
    Cross_Sector_Dependency VARCHAR(255),
    Severity_Score INT,
    Is_Major ENUM('Yes', 'No'),
    Potential_Impact VARCHAR(255),
    Remediation_Steps_Taken TEXT,
    Lessons_Learned TEXT,
    PRIMARY KEY (CISA_Incident_ID, Impact_ID),
    CHECK (Functional_Impact IN (
        'NO IMPACT', 
        'NO IMPACT TO SERVICES', 
        'MINIMAL IMPACT TO NON-CRITICAL SERVICES', 
        'MINIMAL IMPACT TO CRITICAL SERVICES', 
        'SIGNIFICANT IMPACT TO NON-CRITICAL SERVICES', 
        'DENIAL OF NON-CRITICAL SERVICES'
    )),
    CHECK (Information_Impact IN (
        'NO IMPACT',
        'SUSPECTED BUT NOT IDENTIFIED',
        'PRIVACY DATA BREACH',
        'PROPRIETARY INFORMATION BREACH',
        'DESTRUCTION OF NON-CRITICAL SYSTEMS',
        'CRITICAL SYSTEMS DATA BREACH',
        'CORE CREDENTIAL COMPROMISE',
        'DESTRUCTION OF CRITICAL SYSTEM'
    )),
    CHECK (Recoverability IN ('REGULAR', 'SUPPLEMENTED', 'EXTENDED', 'NOT-RECOVERABLE')),
    FOREIGN KEY (CISA_Incident_ID) REFERENCES INCIDENT(CISA_Incident_ID)
);

-- Creating the HOST_AFFECTED table
CREATE TABLE HOST_AFFECTED(
    CISA_Incident_ID VARCHAR(255),
    Impact_ID VARCHAR(64),
    Host_Name VARCHAR(255),
    Host_Type VARCHAR(255),
    Affected_OS VARCHAR(255),
    Affected_Application VARCHAR(255),
    Primary_Purpose VARCHAR(255),
    PRIMARY KEY (CISA_Incident_ID, Impact_ID, Host_Name),
    FOREIGN KEY (CISA_Incident_ID, Impact_ID) REFERENCES IMPACT_FACTOR(CISA_Incident_ID, Impact_ID)
);

-- Creating the DATA_AFFECTED table
CREATE TABLE DATA_AFFECTED(
    CISA_Incident_ID VARCHAR(255),
    Impact_ID VARCHAR(64), 
    Impacted_Records INT,
    Impact_Type ENUM('Access', 'Exposure'),
    PRIMARY KEY (CISA_Incident_ID, Impact_ID),
    FOREIGN KEY (CISA_Incident_ID, Impact_ID) REFERENCES IMPACT_FACTOR(CISA_Incident_ID, Impact_ID)
);

-- Creating the IP_ADDRESS table
CREATE TABLE IP_ADDRESS(
    CISA_Incident_ID VARCHAR(255),
    Impact_ID VARCHAR(64),
    Host_Name VARCHAR(255),
    IP_Add VARCHAR(45), -- Supports both IPv4 and IPv6
    PRIMARY KEY (CISA_Incident_ID, Impact_ID, Host_Name, IP_Add),
    FOREIGN KEY (CISA_Incident_ID, Impact_ID, Host_Name) REFERENCES HOST_AFFECTED(CISA_Incident_ID, Impact_ID, Host_Name)
);

-- Creating the RELEVANT_DATA_TYPE table
CREATE TABLE RELEVANT_DATA_TYPE(
    CISA_Incident_ID VARCHAR(255),
    Impact_ID VARCHAR(255),
    Data_Type VARCHAR(255),
    PRIMARY KEY (CISA_Incident_ID, Impact_ID, Data_Type),
    FOREIGN KEY (CISA_Incident_ID, Impact_ID) REFERENCES DATA_AFFECTED(CISA_Incident_ID, Impact_ID)
);

-- Creating the REPORTS table
CREATE TABLE REPORTS(
    SSN int, 
    Report_ID VARCHAR(255),
    Reporter_Type ENUM('Submitter', 'POC', 'Both'),
    PRIMARY KEY (SSN, Report_ID),
    FOREIGN KEY (SSN) REFERENCES PERSON(SSN),
    FOREIGN KEY (Report_ID) REFERENCES REPORT(Report_ID)
);

-- Creating the AFFECTS table
CREATE TABLE AFFECTS(
    CISA_Incident_ID VARCHAR(255),
    Victim_ID VARCHAR(255),
    Primary_Affected_Sector VARCHAR(255),
    Location_Address VARCHAR(255),
    Location_Contact_Details VARCHAR(255),
    PRIMARY KEY (CISA_Incident_ID, Victim_ID),
    FOREIGN KEY (CISA_Incident_ID) REFERENCES INCIDENT(CISA_Incident_ID),
    FOREIGN KEY (Victim_ID) REFERENCES ORGANIZATION(Victim_ID)
);

-- Creating the INVOLVES table
CREATE TABLE INVOLVES(
    CISA_Incident_ID VARCHAR(255),
    Victim_ID VARCHAR(255),
    Involvement_Type ENUM('Indirectly', 'Supporting', 'Both'),
    Notified ENUM('Yes', 'No'),
    PRIMARY KEY (CISA_Incident_ID, Victim_ID),
    FOREIGN KEY (CISA_Incident_ID) REFERENCES INCIDENT(CISA_Incident_ID),
    FOREIGN KEY (Victim_ID) REFERENCES ORGANIZATION(Victim_ID)
);

DROP TABLE IF EXISTS IP_ADDRESS;
DROP TABLE IF EXISTS RELEVANT_DATA_TYPE;
DROP TABLE IF EXISTS DATA_AFFECTED;
DROP TABLE IF EXISTS HOST_AFFECTED;
DROP TABLE IF EXISTS IMPACT_FACTOR;
DROP TABLE IF EXISTS REPORTS;
DROP TABLE IF EXISTS AFFECTS;
DROP TABLE IF EXISTS INVOLVES;