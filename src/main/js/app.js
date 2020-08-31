const React = require('react'); 
const ReactDOM = require('react-dom'); 
const client = require('./client'); 
const follow = require('./follow');

const root = '/api'

class App extends React.Component {
    constructor (props) {
        super(props);
        this.state = {democertificates: [],attributes: [],pageSize: 2, links: {}};
        this.updatePageSize = this.updatePageSize.bind(this);
		this.onCreate = this.onCreate.bind(this);
		this.onDelete = this.onDelete.bind(this);
		this.onNavigate = this.onNavigate.bind(this);
    }

    componentDidMount() {
        this.loadFromServer(this.state.pageSize);
    }

    loadFromServer(pageSize) {
        follow(client, root, [
            {rel: 'democertificates', params: {size: pageSize}}
        ]).then(certificateCollection => {
            return client({
                method: 'GET',
                path: certificateCollection.entity._links.profile.href,
                headers: {'Accept': 'application/schema+json'}
            }).then(schema => {
                    this.schema = schema.entity;
                    return certificateCollection;
            });
        }).done(certificateCollection => {
            this.setState({
                democertificates: certificateCollection.entity._embedded.democertificates,
                attributes: Object.keys(this.schema.properties),
                pageSize: pageSize,
                links: certificateCollection.entity._links
            });
        });
    }

    onDelete(democertificate) {
        client({method: 'DELETE',path: democertificate._links.self.href}).done(response => {
            this.loadFromServer(this.state.pageSize);
        });
    }

    onNavigate(navUri) {
        client({method: 'GET', path: navUri}).done(certificateCollection => {
            this.setState({
                democertificates: certificateCollection.entity._embedded.democertificates,
                attributes: this.state.attributes,
                pageSize: this.state.pageSize,
                links: certificateCollection.entity._links
            });
        });
    }

    

    onCreate(newCertificate) {
        follow(client,root,['democertificates']).then(certificateCollection => {
            return client({
                method: 'POST',
                path: certificateCollection.entity._links.self.href,
                entity: newCertificate,
                headers: {'Content-Type': 'application/json'}
            })
        }).then(response => {
            return follow(client,root, [
                {rel: 'democertificates',params:{'size': this.state.pageSize}}]);
            }).done(response => {
                if(typeof response.entity._links.last !== 'undefined') {
                    this.onNavigate(response.entity._links.last.href);
                } else {
                    this.onNavigate(response.entity._links.self.href);
                }
        });
    }

    updatePageSize(pageSize) {
        if(pageSize !== this.state.pageSize) {
            this.loadFromServer(pageSize);
        }
    }

    render() {
        return (
            <div>
                <CreateDialog attributes={this.state.attributes} onCreate={this.onCreate}/>
                <DemoCertificateList democertificates={this.state.democertificates}
                    links={this.state.links}
                    pageSize={this.state.pageSize}
                    onNavigate={this.onNavigate}
                    onDelete={this.onDelete}
                    updatePageSize={this.updatePageSize}/>
            </div>
        )
    }
}

class DemoCertificateList extends React.Component{
    constructor(props) {
		super(props);
		this.handleNavFirst = this.handleNavFirst.bind(this);
		this.handleNavPrev = this.handleNavPrev.bind(this);
		this.handleNavNext = this.handleNavNext.bind(this);
		this.handleNavLast = this.handleNavLast.bind(this);
		this.handleInput = this.handleInput.bind(this);
    }

    handleInput(e) {
		e.preventDefault();
		const pageSize = ReactDOM.findDOMNode(this.refs.pageSize).value;
		if (/^[0-9]+$/.test(pageSize)) {
			this.props.updatePageSize(pageSize);
		} else {
			ReactDOM.findDOMNode(this.refs.pageSize).value =
				pageSize.substring(0, pageSize.length - 1);
		}
	}

    handleNavFirst(e) {
        e.preventDefault();
        this.props.onNavigate(this.props.links.first.href);
    }
    handleNavPrev(e) {
        e.preventDefault();
        this.props.onNavigate(this.props.links.prev.href);
    }
    handleNavNext(e) {
        e.preventDefault();
        this.props.onNavigate(this.props.links.next.href);
    }
    handleNavLast(e) {
        e.preventDefault();
        this.props.onNavigate(this.props.links.last.href);
    }

    render() {
        const democertificates = this.props.democertificates.map(democertificate =>
            <DemoCertificate key={democertificate._links.self.href} democertificate={democertificate}
                onDelete={this.props.onDelete}/>
        );
        const navLinks = [];
        if("first" in this.props.links) {
            navLinks.push(<button key="first" onClick={this.handleNavFirst}>&lt;&lt;</button>);
        }
        if("prev" in this.props.links) {
            navLinks.push(<button key="prev" onClick={this.handleNavPrev}>&lt;&lt;</button>);
        }
        if("next" in this.props.links) {
            navLinks.push(<button key="next" onClick={this.handleNavNext}>&lt;&lt;</button>);
        }
        if("last" in this.props.links) {
            navLinks.push(<button key="last" onClick={this.handleNavLast}>&lt;&lt;</button>);
        }
        return (
            <div>
                <input ref="pageSize" defaultValue={this.props.pageSize} onInput={this.handleInput}/>
                <table>
                    <tbody>
                        <tr>
                            <th>Certificate Name</th>
                            <th>Certificate SubjectDN</th>
                            <th>Signed Certificate</th>
                        </tr>
                        {democertificates}
                    </tbody>
                </table>
                <div>
                    {navLinks}
                </div>
            </div>
        )
    }
}

class DemoCertificate extends React.Component{
    constructor(props) {
        super(props);
        this.handleDelete = this.handleDelete.bind(this);
    }

    handleDelete() {
        this.props.onDelete(this.props.democertificate);
    }
    render() {
        return (
            <tr>
                <td>{this.props.democertificate.certName}</td>
                <td>{this.props.democertificate.certSubjectDN}</td>
                <td>{this.props.democertificate.certASN1}</td>
                <td>
                    <button onClick={this.handleDelete}>Delete</button>
                </td>
            </tr>
        )
    }
}

class CreateDialog extends React.Component {
    constructor(props) {
        super(props);
        this.handleSubmit = this.handleSubmit.bind(this);
    }

    handleSubmit(e) {
        e.preventDefault();
        const newCertificate = {};
        this.props.attributes.forEach(attribute => {
            newCertificate[attribute] =
            ReactDOM.findDOMNode(this.refs[attribute]).value.trim();
        });
        this.props.onCreate(newCertificate);

        // Clear out the dialog's inputs
        this.props.attributes.forEach(attribute => {
            ReactDOM.findDOMNode(this.refs[attribute]).value = '';
        });

        // Navigate away from the dialog to hide it
        window.location = '#';
    }

    render() {

        const inputs = this.props.attributes.map(attribute =>
                <p key={attribute}>
                    <input type="text" placeholder={attribute} ref={attribute} className="field"/>
                </p>
            );

        return (
            <div>
                <a href="#createCertificate">Create</a>
                <div id="createCertificate" className="modalDialog">
                    <div>
                        <a href="#" title="Close" className="close">X</a>
                        <h2>Create new certificate</h2>
                        <form>
                            {inputs}
                            <button onClick={this.handleSubmit}>Create</button>
                        </form>
                    </div> 
                </div>
            </div>
        )
    }
}

ReactDOM.render(
    <App />,document.getElementById('react')
)