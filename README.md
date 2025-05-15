Household Services Application
 How I approached the problem statement
 ;
 I started by creating an ER diagram, which laid a solid foundation for my project and made the development 
process smooth and organized. Gradually, I implemented all the required functionalities as specified for the 
application
• Frameworks and libraries used;
 • Standard Python Libraries:
 1) datetime- For handling date and time-related operations.
 2) enum- For defining enumerations (custom data types with named values).
 3) os- For interacting with the operating system (e.g., file handling, paths).
 4) re- For working with regular expressions.
 5) Flask Libraries:
 6. flask:
 o
 o
 o
 o
 Flask- The main framework for building web applications.
 flash - For sending one-time messages to the user (e.g., success or error 
notifications).
 redirect- For redirecting users to a different URL.
 request- For handling incoming requests (e.g., form data, query parameters).
 send_from_directory- For serving files from a directory.
 o
o
 url_for- For building URLs dynamically.
 o
 o
 render_template- For rendering HTML templates.
 session - For handling session data.
 7.flask_sqlalchemy:
 o
 SQLAlchemy-An ORM (Object-Relational Mapper) for 
interacting with databases.
 8.flask_migrate:
 o
 Migrate - For database migrations (schema changes)
 9.flask_login:
 o
 LoginManager- For managing user authentication.
 UserMixin- A helper class for managing user sessions.
 o
o
 current_user- To access the currently logged-in user.
 o
 o
 o
 login_required- A decorator to restrict access to authenticated users.
 login_user- To log in a user programmatically.
 logout_user- To log out the current user.
 • SQLAlchemy Libraries:
 10.sqlalchemy:
 o
 o
 o
 Column, ForeignKey, Integer- For defining database table schemas.
 or_, func- For performing complex queries and using SQL functions.
 exc.SQLAlchemyError- For handling SQLAlchemy-related exceptions.
 • Werkzeug Libraries:
 11.werkzeug.security:
 o
 check_password_hash, generate_password_hash- For securely hashing and verifying 
passwords.
 12.werkzeug.utils:
 secure_filename- For safely handling uploaded file names
