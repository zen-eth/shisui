import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
// import HomepageFeatures from '@site/src/components/HomepageFeatures'; // Remove unused import

import Heading from '@theme/Heading';
import styles from './index.module.css';

function HomepageHeader() {
  const {siteConfig} = useDocusaurusContext();
  return (
    <header className={clsx('hero hero--primary', styles.heroBanner)}>
      <div className="container">
        <Heading as="h1" className="hero__title">
          {siteConfig.title}
        </Heading>
        <p className="hero__subtitle">{siteConfig.tagline}</p>
        <div className={styles.buttons}>
          <Link
            className="button button--secondary button--lg"
            to="/docs/intro">
            Learn More
          </Link>
        </div>
      </div>
    </header>
  );
}

export default function Home() {
  const {siteConfig} = useDocusaurusContext();
  return (
    <Layout
      // title={`Hello from ${siteConfig.title}`} // Use a more static title or remove if not needed
      title="Shisui - Ethereum Portal Client"
      description="Shisui is an Ethereum portal client written in Go, implementing the Ethereum Portal Network protocol.">
      <HomepageHeader />
      <main>
        {/* <HomepageFeatures /> */} 
        {/* Remove or replace HomepageFeatures with more relevant content or keep it simple */}
        <div className="container" style={{padding: '2rem 0', textAlign: 'center'}}>
          <p>
            Explore the documentation to understand how Shisui works and how to integrate it.
          </p>
        </div>
      </main>
    </Layout>
  );
}
