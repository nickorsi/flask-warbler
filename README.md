<!-- Improved compatibility of back to top link: See: https://github.com/othneildrew/Best-README-Template/pull/73 -->
<a name="readme-top"></a>
<!--
*** Thanks for checking out the Best-README-Template. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Don't forget to give the project a star!
*** Thanks again! Now go create something AMAZING! :D
-->



<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->

<!-- PROJECT LOGO -->
<h3 align="center">🐤Warbler🐥</h3>
<br />
<div align="center">
  <a href="https://github.com/nickorsi/satly">
    <img src="static/images/warbler_demo.gif" alt="App Demo Gif">
  </a>
  <p align="center">
    A social media/messaging app of the aves variety!
    <br />
    <a href="https://nick-orsi-warbler.onrender.com/">View Demo</a>
    ·
    <a href="https://github.com/nickorsi/flask-warbler/issues">Report Bug</a>
    ·
    <a href="https://github.com/nickorsi/flask-warbler/issues">Request Feature</a>
  </p>
</div>

<div align="center">

  ![GitHub top language](https://img.shields.io/github/languages/top/nickorsi/flask-warbler)
  ![GitHub repo size](https://img.shields.io/github/repo-size/nickorsi/flask-warbler)
  ![GitHub repo file or directory count](https://img.shields.io/github/directory-file-count/nickorsi/flask-warbler)
  ![GitHub last commit](https://img.shields.io/github/last-commit/nickorsi/flask-warbler)

</div>


<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Seeding Data</a></li>
      </ul>
    </li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

Warbler is an social app where users can create a user profile, view and follow/unfollow other profiles, create messages, and view and like/unlike other messages.

This is a full-stack application written in Python using Flask as the web framework and Flask-SQLAlchemy as an Object Relational Mapper (ORM). This is a traditional HTML serving application. It incoporates the use of flask-bcrypt to save hashed versions of user passwords in the database and to securely authenticate user log-ins.

Deployed using Render to host the backend code and ElephantSQL to host the database.

Some tools and concepts covered during this project:

* Working within an existing codebase to fix issues without making new ones
* Working with Many-to-Many relations that are on the same table (users following users)
* Using Flask-Bcrypt to securly save passwords and authenticate users
* Form validation and error handling with Flask-WTForms
* Rendering HTML dynamically with the use of Jinja
* Styling with Bootstrap and traditional CSS


### Database Design

<div align="center">
  <a href="static/images/database-design.png">
    <img src="static/images/database-design.png" alt="Database design">
  </a>
</div>


<p align="right">(<a href="#readme-top">back to top</a>)</p>



### Built With

* [![Python][Python.com]][Python-url]
* [![HTML5][HTML5.com]][HTML5-url]
* [![CSS3][CSS3.com]][CSS3-url]
* [![PostgreSQL][PostgreSQL.com]][PostgreSQL-url]
* [![Bootstrap][Bootstrap.com]][Bootstrap-url]
* [![Flask][Flask.com]][Flask-url]
* [![SQLAlchemy][SQLAlchemy.com]][SQLAlchemy-url]
* [![Jinja][Jinja.com]][Jinja-url]
* [![WTForms][WTForms.com]][WTForms-url]
* [![Render][Render.com]][Render-url]
* [![ElephantSQL][ElephantSQL.com]][ElephantSQL-url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- GETTING STARTED -->
## Getting Started

To get a local copy up and running follow these simple example steps. Note that you will need to connect your own AWS S3 bucket to allow the app to fully function.

1. Clone this repo at your desired directory.

  ```sh
  $ git clone https://github.com/nickorsi/flask-warbler.git
  ```
2. Within this new directory, create a virtual environment.

  ```sh
  $ python3 -m venv venv
  ```
3. Activate the venv.

  ```sh
  $ source venv/bin/activate
  ```
4. Install the requirements saved within the requirements.txt file.

  ```sh
  (venv) $ pip3 install -r requirements.txt
  ```
5. Run server.

  ```sh
  (venv) $ flask run
  ```
  Note: Mac users may need to run the flask server on port 5001 using the below command.

    ```sh
    (venv) $ flask run -p 5001
    ```

6. Create a .env file and assign the following keys, REMEMBER TO ADD THIS TO YOUR .gitignore FILE!
  ```python
    SECRET_KEY=abc123
    DATABASE_URL=postgresql:///warbler
  ```

### Seeding Data

Seed the database with the radonmly generated users. This requires PostgreSQL to be installed.

1. Create the warbler db:
   ```sh
   (venv) $ psql
   =# CREATE DATABASE warbler;
   ```

2. Now seed the database with the randomly generated user content with the seed file.
  ```sh
   (venv) $ python seed.py
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- ROADMAP -->
## Roadmap

- [ ] Add more tests for the existing views and users
- [ ] Add ability to exit a message card and go back to the list of messages
- [ ] DRY up templates, authorization code, and URLs
- [ ] Make a change password form
- [ ] Optimize queries


<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- CONTACT -->
## Contact

Nick Orsi
* [<img src="https://img.shields.io/badge/linkedin-%230077B5.svg?style=for-the-badge&logo=linkedin&logoColor=white" alt="Linkedin Logo">](https://www.linkedin.com/in/nicholas-orsi-18ab8382/)
* [www.nickorsi.com](https://www.nickorsi.com/)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- ACKNOWLEDGMENTS -->
## Acknowledgments
This contains starter code generated from [Rithm School](https://www.rithmschool.com/) as part of the curriculum in December 2023.

* [Seth Lawrence](https://github.com/Seth-Lawrence): Pair Programming Partner
* [Best README Template](https://github.com/othneildrew/Best-README-Template)
* [Mardown Badges](https://github.com/Ileriayo/markdown-badges)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[Python.com]: https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54
[Python-url]: https://www.python.org/
[JavaScript.com]: https://img.shields.io/badge/javascript-%23323330.svg?style=for-the-badge&logo=javascript&logoColor=%23F7DF1E
[JavaScript-url]: https://developer.mozilla.org/en-US/docs/Web/JavaScript
[HTML5.com]: https://img.shields.io/badge/html5-%23E34F26.svg?style=for-the-badge&logo=html5&logoColor=white
[HTML5-url]: https://developer.mozilla.org/en-US/docs/Web/HTML
[CSS3.com]: https://img.shields.io/badge/css3-%231572B6.svg?style=for-the-badge&logo=css3&logoColor=white
[CSS3-url]: https://developer.mozilla.org/en-US/docs/Web/CSS
[PostgreSQL.com]: https://img.shields.io/badge/postgres-%23316192.svg?style=for-the-badge&logo=postgresql&logoColor=white
[PostgreSQL-url]: https://www.postgresql.org/
[Bootstrap.com]: https://img.shields.io/badge/Bootstrap-563D7C?style=for-the-badge&logo=bootstrap&logoColor=white
[Bootstrap-url]: https://getbootstrap.com
[Flask.com]: https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white
[Flask-url]: https://flask.palletsprojects.com/en/3.0.x/
[SQLAlchemy.com]: https://img.shields.io/badge/SQLAlchemy-%23D63113?style=for-the-badge
[SQLAlchemy-url]: https://flask-sqlalchemy.palletsprojects.com/en/3.1.x/
[Jinja.com]: https://img.shields.io/badge/jinja-white.svg?style=for-the-badge&logo=jinja&logoColor=black
[Jinja-url]: https://jinja.palletsprojects.com/en/3.1.x/
[WTForms.com]: https://img.shields.io/badge/WTForms-blue
[WTForms-url]: https://flask-wtf.readthedocs.io/en/1.2.x/
[AWS.com]: https://img.shields.io/badge/AWS-%23FF9900.svg?style=for-the-badge&logo=amazon-aws&logoColor=white
[AWS-url]: https://aws.amazon.com/free/?gclid=CjwKCAjwte-vBhBFEiwAQSv_xQ9cNbAh7bqze8OHPqAjkwd9WAcrT9ebcC_gjiMhb5iNz2KDvq9QARoCrkkQAvD_BwE&trk=fce796e8-4ceb-48e0-9767-89f7873fac3d&sc_channel=ps&ef_id=CjwKCAjwte-vBhBFEiwAQSv_xQ9cNbAh7bqze8OHPqAjkwd9WAcrT9ebcC_gjiMhb5iNz2KDvq9QARoCrkkQAvD_BwE:G:s&s_kwcid=AL!4422!3!592542020599!e!!g!!aws!1644045032!68366401852&all-free-tier.sort-by=item.additionalFields.SortRank&all-free-tier.sort-order=asc&awsf.Free%20Tier%20Types=*all&awsf.Free%20Tier%20Categories=*all
[Render.com]: https://img.shields.io/badge/Render-%46E3B7.svg?style=for-the-badge&logo=render&logoColor=white
[Render-url]: https://render.com/
[ElephantSQL.com]: https://img.shields.io/badge/ElephantSQL-%233F9BBF?style=for-the-badge
[ElephantSQL-url]: https://www.elephantsql.com/
