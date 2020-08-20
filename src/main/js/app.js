const React = require('react'); 
const ReactDOM = require('react-dom'); 
const client = require('./client'); 

class App extends React.Component {
    constructor (props) {
        super(props);
        this.state = {democertificates: []};
    }

    componentDidMount() {
        client({method: 'GET', path: '/api/democertificates'}).done(response => {
            this.setState({democertificates: response.entity._embedded.democertificates});
        });
    }

    render() {
        return (
            <DemoCertificateList democertificates={this.state.democertificates}/>
        )
    }
}

class DemoCertificateList extends React.Component{
    render() {
        const democertificates = this.props.democertificates.map(democertificate =>
            <DemoCertificate key={democertificate._links.self.href} democertificate={democertificate}/>
        );
        return (
            <table>
                <tbody>
                    <tr>
                        <th>Certificate Name</th>
                        <th>Certificate SubjectDN</th>
                    </tr>
                    {democertificates}
                </tbody>
            </table>
        )
    }
}

class DemoCertificate extends React.Component{
    render() {
        return (
            <tr>
                <td>{this.props.democertificate.certname}</td>
                <td>{this.props.democertificate.certsubjectdn}</td>
            </tr>
        )
    }
}

ReactDOM.render(
    <App />,document.getElementById('react')
)