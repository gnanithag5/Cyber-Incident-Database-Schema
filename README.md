# Cyber-Incident-Database-Schema

### **Overview**

This project defines a relational database schema for tracking cyber incidents, including their impact, affected hosts, data breaches, involved organizations, and reports submitted. The schema is designed with normalization principles and integrity constraints to ensure data consistency.

### **Features**

1. Implements Primary Keys to uniquely identify records. Uses Foreign Keys to maintain relationships between tables, ensuring referential integrity.
2. Schema is designed to minimize redundancy and optimize performance. Data is structured in multiple tables for better scalability and efficient querying.
3. Modular design allows for future expansion, such as adding new impact categories or more detailed threat classifications.
4. Uses data type restrictions to prevent inconsistent or invalid entries. Ensures accurate relationships between incidents, organizations, and affected entities.
